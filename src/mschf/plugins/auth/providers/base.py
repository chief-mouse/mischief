class BaseAuthenticator:
    # Interactive providers (e.g. real OIDC) open a browser and block; the UI must
    # run their authenticate() off the main thread. Mock providers are instant.
    interactive = False

    def __init__(self, name, display_name):
        self.name = name
        self.display_name = display_name

    def authenticate(self, **kwargs):
        """Perform cryptographic or local credential verification.
        Returns a dict with {success: bool, identity: str, metadata: dict, error: str}
        """
        raise NotImplementedError("Authenticators must implement 'authenticate'")
