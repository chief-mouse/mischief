"""HTTP hub for hub-and-spoke ledger sync.

The hub holds the authoritative copy of one or more ``.msf`` containers and is
trusted for ORDERING and AVAILABILITY only — never integrity. Every submitted
transaction is verified by ``MSFStorage.execute_signed`` (signature, hash-chain
position, CA trust, RBAC, authorizer).

Uses ``ThreadingHTTPServer`` so long-poll event waits do not block other
requests. Single-writer is explicit: a per-container ``threading.Lock`` is held
around the POST-submit ``execute_signed`` path. Reads (head / transactions /
file / events) do not take that lock.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from mschf.storage import MSFStorage

# Long-poll defaults / caps for GET .../events
_DEFAULT_EVENTS_TIMEOUT = 25
_MAX_EVENTS_TIMEOUT = 30


def _open_storage(path, ca_cert_path=None, trust_dir=None, allow_homed_writes=True):
    """Open MSFStorage with check_same_thread=False.

    The hub's request handlers run on server threads; callers (tests, admin
    tools) may also touch the same process. Per-container write locks make
    concurrent SQLite use safe on the submit path; we only relax the
    thread-affinity guard. MSFStorage does not expose the connect flag, so we
    temporarily wrap ``sqlite3.connect`` for this construction only.

    Hub storages always pass ``allow_homed_writes=True`` — the hub *is* the
    chain serializer for homed containers.
    """
    orig = sqlite3.connect

    def _connect(*args, **kwargs):
        kwargs.setdefault('check_same_thread', False)
        return orig(*args, **kwargs)

    sqlite3.connect = _connect
    try:
        return MSFStorage(
            path,
            ca_cert_path=ca_cert_path,
            trust_dir=trust_dir,
            allow_homed_writes=allow_homed_writes,
        )
    finally:
        sqlite3.connect = orig


def _b64e(data) -> str:
    if data is None:
        return ''
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.b64encode(bytes(data)).decode('ascii')


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode('ascii') if isinstance(s, str) else s)


def _pem_str(val) -> str:
    if val is None:
        return ''
    if isinstance(val, bytes):
        return val.decode('utf-8')
    return str(val)


class MSFHub:
    """Authoritative hub for one directory of ``.msf`` containers."""

    def __init__(
        self,
        containers_dir,
        hub_cert_path,
        hub_key_path,
        key_passphrase=None,
        host='127.0.0.1',
        port=0,
        ca_cert_path=None,
        trust_dir=None,
    ):
        self.containers_dir = os.path.abspath(containers_dir)
        self.hub_cert_path = hub_cert_path
        self.hub_key_path = hub_key_path
        self.key_passphrase = key_passphrase
        self.ca_cert_path = ca_cert_path
        self.trust_dir = trust_dir
        self._storages = {}  # container_id -> MSFStorage
        self._storages_lock = threading.Lock()
        self._write_locks = {}  # container_id -> Lock (POST submit path)
        self._write_locks_guard = threading.Lock()
        self._conditions = {}  # container_id -> Condition (events long-poll)
        self._conditions_guard = threading.Lock()

        with open(hub_cert_path, 'rb') as f:
            self._hub_cert_pem = f.read()
        with open(hub_key_path, 'rb') as f:
            key_bytes = f.read()
        pw = None
        if key_passphrase is not None:
            pw = key_passphrase.encode('utf-8') if isinstance(key_passphrase, str) else key_passphrase
        self._hub_key = serialization.load_pem_private_key(
            key_bytes, password=pw, backend=default_backend()
        )
        self._hub_cert_pem_str = self._hub_cert_pem.decode('utf-8')

        handler = self._make_handler()
        self.httpd = ThreadingHTTPServer((host, port), handler)
        self.httpd.daemon_threads = True

    # ------------------------------------------------------------------
    # Container access
    # ------------------------------------------------------------------

    def list_containers(self):
        if not os.path.isdir(self.containers_dir):
            return []
        ids = []
        for name in sorted(os.listdir(self.containers_dir)):
            if name.lower().endswith('.msf') and os.path.isfile(
                os.path.join(self.containers_dir, name)
            ):
                ids.append(os.path.splitext(name)[0])
        return ids

    def container_path(self, container_id):
        # v1: container id is the filename stem; reject path separators.
        if not container_id or '/' in container_id or '\\' in container_id or '..' in container_id:
            return None
        path = os.path.join(self.containers_dir, f'{container_id}.msf')
        if not os.path.isfile(path):
            return None
        return path

    def get_storage(self, container_id):
        path = self.container_path(container_id)
        if path is None:
            return None
        with self._storages_lock:
            if container_id not in self._storages:
                self._storages[container_id] = _open_storage(
                    path,
                    ca_cert_path=self.ca_cert_path,
                    trust_dir=self.trust_dir,
                    allow_homed_writes=True,
                )
            return self._storages[container_id]

    def _write_lock(self, container_id):
        with self._write_locks_guard:
            lock = self._write_locks.get(container_id)
            if lock is None:
                lock = threading.Lock()
                self._write_locks[container_id] = lock
            return lock

    def _condition(self, container_id):
        with self._conditions_guard:
            cond = self._conditions.get(container_id)
            if cond is None:
                cond = threading.Condition()
                self._conditions[container_id] = cond
            return cond

    # ------------------------------------------------------------------
    # Head + attestation
    # ------------------------------------------------------------------

    def head_payload_str(self, container_id, next_seq, prev_hash):
        return json.dumps(
            {'container': container_id, 'next_seq': next_seq, 'prev_hash': prev_hash},
            sort_keys=True,
        )

    def sign_attestation(self, payload_str: str) -> bytes:
        return self._hub_key.sign(
            payload_str.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

    def build_head_response(self, container_id, storage):
        next_seq, prev_hash = storage.get_chain_head()
        payload_str = self.head_payload_str(container_id, next_seq, prev_hash)
        sig = self.sign_attestation(payload_str)
        return {
            'container': container_id,
            'next_seq': next_seq,
            'prev_hash': prev_hash,
            # Stable per-.msf identity used in v3 signed transaction payloads.
            # Spokes sign against this claim (and may refuse a mismatch with
            # their local replica's uid).
            'container_uid': storage.container_uid,
            'attestation': {
                'payload': payload_str,
                'signature': _b64e(sig),
                'hub_cert': self._hub_cert_pem_str,
            },
        }

    def serialize_container_file(self, storage) -> bytes:
        """Consistent snapshot via sqlite3 backup to a temp file.

        Delegates to ``MSFStorage.backup_to_bytes``, which holds the storage
        connection lock for the whole backup so concurrent ``execute_signed``
        cannot race the shared hub connection while the snapshot is taken.
        """
        return storage.backup_to_bytes()

    def transactions_since(self, storage, since_seq: int):
        # fetch_ledger_rows_since holds storage._conn_lock only for the SELECT
        # (materialized rows). wait_for_events must not hold that lock across
        # cond.wait — it only calls us briefly between waits.
        rows = storage.fetch_ledger_rows_since(since_seq)
        out = []
        for (txn_id, query, params_str, signature, pub_key, ts, seq, prev_hash,
             payload_fmt) in rows:
            try:
                params = json.loads(params_str) if params_str else []
            except json.JSONDecodeError:
                params = []
            out.append({
                'id': txn_id,
                'query': query,
                'params': params,
                'signature_b64': _b64e(signature),
                'pub_key': _pem_str(pub_key),
                'timestamp': ts,
                'seq': seq,
                'prev_hash': prev_hash,
                'payload_fmt': payload_fmt,
            })
        return out

    def wait_for_events(self, container_id, storage, since_seq: int, timeout: float):
        """Long-poll helper: return rows with seq > since_seq, waiting up to timeout.

        Empty list on timeout is a normal response (not an error). Check-and-wait
        under the per-container Condition so a submit that commits between the
        empty check and wait cannot lose its notify.
        """
        cond = self._condition(container_id)
        deadline = time.monotonic() + max(0.0, float(timeout))
        with cond:
            while True:
                rows = self.transactions_since(storage, since_seq)
                if rows:
                    return rows
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return []
                cond.wait(timeout=remaining)

    def notify_events(self, container_id):
        """Wake all long-poll waiters after a successful submit commit."""
        cond = self._condition(container_id)
        with cond:
            cond.notify_all()

    # ------------------------------------------------------------------
    # HTTP handler
    # ------------------------------------------------------------------

    def _make_handler(self):
        hub = self

        class HubHandler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                # Quiet by default; tests print their own progress.
                pass

            def _send_json(self, code, obj):
                body = json.dumps(obj).encode('utf-8')
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _send_bytes(self, code, data, content_type='application/octet-stream'):
                self.send_response(code)
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _read_json(self):
                length = int(self.headers.get('Content-Length') or 0)
                raw = self.rfile.read(length) if length else b''
                if not raw:
                    return {}
                return json.loads(raw.decode('utf-8'))

            def do_GET(self):
                parsed = urlparse(self.path)
                path = parsed.path.rstrip('/') or '/'
                parts = [p for p in path.split('/') if p]

                # GET /containers
                if parts == ['containers']:
                    self._send_json(200, {'containers': hub.list_containers()})
                    return

                # GET /containers/<id>/...
                if len(parts) >= 2 and parts[0] == 'containers':
                    container_id = parts[1]
                    storage = hub.get_storage(container_id)
                    if storage is None:
                        self._send_json(404, {'error': 'unknown_container', 'detail': container_id})
                        return

                    if len(parts) == 3 and parts[2] == 'head':
                        self._send_json(200, hub.build_head_response(container_id, storage))
                        return

                    if len(parts) == 3 and parts[2] == 'transactions':
                        qs = parse_qs(parsed.query)
                        try:
                            since_seq = int(qs.get('since_seq', ['0'])[0])
                        except (TypeError, ValueError):
                            self._send_json(400, {'error': 'bad_request', 'detail': 'since_seq must be int'})
                            return
                        rows = hub.transactions_since(storage, since_seq)
                        self._send_json(200, {'rows': rows})
                        return

                    if len(parts) == 3 and parts[2] == 'events':
                        qs = parse_qs(parsed.query)
                        try:
                            since_seq = int(qs.get('since_seq', ['0'])[0])
                        except (TypeError, ValueError):
                            self._send_json(400, {
                                'error': 'bad_request',
                                'detail': 'since_seq must be int',
                            })
                            return
                        try:
                            timeout = float(qs.get('timeout', [str(_DEFAULT_EVENTS_TIMEOUT)])[0])
                        except (TypeError, ValueError):
                            self._send_json(400, {
                                'error': 'bad_request',
                                'detail': 'timeout must be a number',
                            })
                            return
                        if timeout < 0:
                            timeout = 0.0
                        if timeout > _MAX_EVENTS_TIMEOUT:
                            timeout = float(_MAX_EVENTS_TIMEOUT)
                        rows = hub.wait_for_events(
                            container_id, storage, since_seq, timeout)
                        self._send_json(200, {'rows': rows})
                        return

                    if len(parts) == 3 and parts[2] == 'file':
                        data = hub.serialize_container_file(storage)
                        self._send_bytes(200, data)
                        return

                self._send_json(404, {'error': 'not_found', 'detail': self.path})

            def do_POST(self):
                parsed = urlparse(self.path)
                path = parsed.path.rstrip('/') or '/'
                parts = [p for p in path.split('/') if p]

                # POST /containers/<id>/transactions
                if (
                    len(parts) == 3
                    and parts[0] == 'containers'
                    and parts[2] == 'transactions'
                ):
                    container_id = parts[1]
                    storage = hub.get_storage(container_id)
                    if storage is None:
                        self._send_json(404, {'error': 'unknown_container', 'detail': container_id})
                        return
                    try:
                        body = self._read_json()
                    except (json.JSONDecodeError, UnicodeDecodeError) as e:
                        self._send_json(400, {'error': 'bad_request', 'detail': f'malformed JSON: {e}'})
                        return

                    query = body.get('query')
                    params = body.get('params', [])
                    sig_b64 = body.get('signature_b64')
                    pub_key = body.get('pub_key')
                    if query is None or sig_b64 is None or pub_key is None:
                        self._send_json(400, {
                            'error': 'bad_request',
                            'detail': 'query, signature_b64, and pub_key are required',
                        })
                        return
                    if params is None:
                        params = []

                    try:
                        signature = _b64d(sig_b64)
                    except Exception as e:
                        self._send_json(400, {'error': 'bad_request', 'detail': f'bad signature_b64: {e}'})
                        return

                    # Optional client-declared head (the head the payload was signed
                    # against). Distinguishes stale-head (409) from a corrupt
                    # signature over the current head (403) — both fail the same
                    # crypto check inside execute_signed.
                    client_seq = body.get('seq', None)
                    client_prev = body.get('prev_hash', None)

                    write_lock = hub._write_lock(container_id)
                    with write_lock:
                        cur_seq, cur_prev = storage.get_chain_head()
                        if client_seq is not None:
                            try:
                                client_seq = int(client_seq)
                            except (TypeError, ValueError):
                                self._send_json(400, {
                                    'error': 'bad_request',
                                    'detail': 'seq must be int',
                                })
                                return
                            if client_seq != cur_seq or client_prev != cur_prev:
                                head = hub.build_head_response(container_id, storage)
                                resp = {
                                    'error': 'stale_head',
                                    'detail': (
                                        f'payload signed against seq={client_seq}, '
                                        f'prev_hash={client_prev!r}; current head is '
                                        f'seq={cur_seq}, prev_hash={cur_prev!r}'
                                    ),
                                }
                                resp.update(head)
                                self._send_json(409, resp)
                                return

                        try:
                            storage.execute_signed(query, params, signature, pub_key)
                        except PermissionError as e:
                            msg = str(e)
                            head = hub.build_head_response(container_id, storage)
                            # Signature failure against current head: if the client
                            # declared a matching head, this is a bad signature (403);
                            # otherwise treat as potentially stale (409) so clients
                            # can re-sign and retry.
                            if 'signed against the current chain head' in msg or (
                                'current chain head' in msg and 'signature' in msg.lower()
                            ):
                                if client_seq is not None:
                                    self._send_json(403, {
                                        'error': 'forbidden',
                                        'detail': msg,
                                    })
                                else:
                                    resp = {'error': 'stale_head', 'detail': msg}
                                    resp.update(head)
                                    self._send_json(409, resp)
                                return
                            self._send_json(403, {'error': 'forbidden', 'detail': msg})
                            return
                        except Exception as e:
                            self._send_json(400, {
                                'error': 'bad_request',
                                'detail': str(e),
                            })
                            return

                        head_resp = hub.build_head_response(container_id, storage)

                    # Wake long-poll waiters after the write lock is released
                    # (committed state is visible; Condition serializes notify
                    # with waiters' empty-check).
                    hub.notify_events(container_id)
                    self._send_json(200, head_resp)
                    return

                self._send_json(404, {'error': 'not_found', 'detail': self.path})

        return HubHandler

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @property
    def address(self):
        return self.httpd.server_address  # (host, port)

    @property
    def url(self):
        host, port = self.httpd.server_address
        # Prefer 127.0.0.1 over 0.0.0.0 for client URLs.
        if host in ('0.0.0.0', ''):
            host = '127.0.0.1'
        return f'http://{host}:{port}'

    def serve_forever(self):
        self.httpd.serve_forever()

    def shutdown(self):
        self.httpd.shutdown()

    def server_close(self):
        for s in self._storages.values():
            try:
                s.close()
            except Exception:
                pass
        self._storages.clear()
        self.httpd.server_close()


def main(argv=None):
    parser = argparse.ArgumentParser(description='mschf ledger sync hub')
    parser.add_argument('containers_dir', help='Directory of .msf containers to serve')
    parser.add_argument('hub_cert', help='Hub service certificate (PEM)')
    parser.add_argument('hub_key', help='Hub service private key (PEM)')
    parser.add_argument('--port', type=int, default=0, help='Listen port (0 = ephemeral)')
    parser.add_argument('--host', default='127.0.0.1', help='Bind address')
    parser.add_argument('--ca-cert', default=None, help='Host CA cert path')
    parser.add_argument('--trust-dir', default=None, help='Extra trust-store directory')
    parser.add_argument('--passphrase', default=None, help='Hub key passphrase')
    args = parser.parse_args(argv)

    hub = MSFHub(
        args.containers_dir,
        args.hub_cert,
        args.hub_key,
        key_passphrase=args.passphrase,
        host=args.host,
        port=args.port,
        ca_cert_path=args.ca_cert,
        trust_dir=args.trust_dir,
    )
    host, port = hub.address
    print(f'mschf hub serving {os.path.abspath(args.containers_dir)} on http://{host}:{port}')
    try:
        hub.serve_forever()
    except KeyboardInterrupt:
        print('\nshutting down')
    finally:
        hub.shutdown()
        hub.server_close()


if __name__ == '__main__':
    main()
