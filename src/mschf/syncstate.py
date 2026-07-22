"""Sync-presentation state for GUI documents.

Kept import-clean of toga so headless tests and CI can exercise it.
May import mschf.storage / mschf.sync (neither pulls toga) but must not
import toga or mschf.msf (import cycle).
"""
import time

from mschf.storage import MSFStorage


def format_sync_status_line(status, connected, has_hub_url=True):
    """Build the GUI sync-status line from cheap local facts only.

    Headless-testable. ``status`` is the dict from ``sync.sync_status`` (no
    network probe). ``connected`` is the subscriber thread's live/offline flag
    (True after any successful poll cycle, including empty timeouts).

    Returns ``None`` when the container is not homed (caller shows nothing).
    """
    if not status or not status.get('homed'):
        return None
    cn = status.get('hub_cn') or '?'
    if not has_hub_url:
        return f"SYNC: hub {cn} — no url configured"
    live = 'live' if connected else 'offline'
    head = status.get('local_next_seq', 0)
    pending = status.get('outbox_pending', 0) or 0
    return f"SYNC: hub {cn} — {live} · head {head} · {pending} pending"


def record_sync_render_facts(status, connected):
    """Snapshot of sync facts that drove the status line (for staleness checks).

    Headless-testable. Call once per redraw from the same ``sync_status`` dict
    already used to format the line — do not recompute status. Returns ``None``
    when not homed (nothing rendered).
    """
    if not status or not status.get('homed'):
        return None
    return {
        'connected': bool(connected),
        'outbox_pending': int(status.get('outbox_pending', 0) or 0),
    }


def is_sync_render_stale(rendered, status, connected):
    """True if a homed container's live facts differ from the last-rendered snapshot.

    ``status`` is from ``sync.sync_status`` without a network probe;
    ``connected`` is the subscriber thread flag. Never raises — bad inputs
    yield False. Unhomed containers are never stale.
    """
    try:
        if not status or not status.get('homed'):
            return False
        if rendered is None:
            return False
        cur_connected = bool(connected)
        cur_pending = int(status.get('outbox_pending', 0) or 0)
        if cur_connected != bool(rendered.get('connected')):
            return True
        if cur_pending != int(rendered.get('outbox_pending', 0) or 0):
            return True
        return False
    except Exception:
        return False


def _sync_subscriber_main(
    path,
    hub_url,
    container_id,
    stop_event,
    hub_cn,
    ca_cert_path,
    trust_dir,
    thread_state,
    poll_timeout=None,
):
    """Long-poll loop for a document subscriber (runs in a daemon thread).

    Opens its **own** ``MSFStorage`` on ``path`` — never touch the document's
    connection or any Toga object. Applied rows bump ``PRAGMA data_version``;
    the existing ``check_external_change`` poll redraws the document.

    ``thread_state`` is a simple namespace (or the Thread itself) with:
    - ``connected``: True after any successful poll cycle (incl. empty timeout)
    - ``last_applied_at``: monotonic time of last non-empty apply
    - ``storage_conn_id``: ``id(conn)`` of this thread's connection (tests)

    ``poll_timeout`` overrides the long-poll wait (seconds); default matches
    ``sync.subscribe``. The first cycle uses a short timeout so the live/offline
    indicator flips without waiting a full long-poll window.
    """
    from mschf import sync as msync

    # Defaults mirror sync.subscribe so behaviour stays aligned.
    full_timeout = (
        float(poll_timeout)
        if poll_timeout is not None
        else float(getattr(msync, '_DEFAULT_EVENTS_TIMEOUT', 25))
    )
    events_slop = getattr(msync, '_EVENTS_HTTP_SLOP', 10)
    backoff_start = getattr(msync, '_BACKOFF_START', 1.0)
    backoff_cap = getattr(msync, '_BACKOFF_CAP', 30.0)
    # First cycle: short park so "live" appears quickly when already in sync.
    first_timeout = min(full_timeout, 2.0)

    thread_state.connected = False
    thread_state.last_applied_at = None
    thread_state.storage_conn_id = None

    sub = MSFStorage(path, ca_cert_path=ca_cert_path, trust_dir=trust_dir)
    thread_state.storage_conn_id = id(sub.conn)
    backoff = backoff_start
    first_cycle = True
    try:
        while not stop_event.is_set():
            since_seq = msync._local_max_seq(sub)
            this_timeout = first_timeout if first_cycle else full_timeout
            try:
                code, data = msync._http_json(
                    'GET',
                    msync._url(
                        hub_url,
                        'containers',
                        container_id,
                        'events',
                        query={
                            'since_seq': since_seq,
                            'timeout': this_timeout,
                        },
                    ),
                    timeout=this_timeout + events_slop,
                )
                if code != 200:
                    raise PermissionError(
                        f'subscribe: events failed ({code}): {data}'
                    )
                # Successful poll cycle (including empty timeout rows) → live.
                thread_state.connected = True
                first_cycle = False
                result = msync.pull_and_apply(
                    sub,
                    hub_url,
                    container_id,
                    expected_hub_cn=hub_cn,
                    ca_cert_path=ca_cert_path,
                    trust_dir=trust_dir,
                )
                backoff = backoff_start
                if result.get('applied', 0) > 0:
                    thread_state.last_applied_at = time.monotonic()
            except Exception as e:
                if stop_event.is_set():
                    break
                if msync._is_connection_error(e) or isinstance(e, TimeoutError):
                    thread_state.connected = False
                    stop_event.wait(timeout=backoff)
                    backoff = min(backoff * 2, backoff_cap)
                    continue
                # Application / crypto glitch — keep looping, stay "connected"
                # only if we had previously succeeded; do not flip offline for
                # a transient 403 (hub is reachable).
                stop_event.wait(timeout=min(backoff, 5.0))
                backoff = min(backoff * 2, backoff_cap)
                continue
    finally:
        try:
            sub.close()
        except Exception:
            pass
