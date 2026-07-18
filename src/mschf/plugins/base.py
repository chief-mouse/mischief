import logging

log = logging.getLogger(__name__)

class BasePlugin:
    def __init__(self, name):
        self.name = name
        self.enabled = True

    def on_load(self, app):
        """Called when the plugin is loaded by the application."""
        log.info(f"on_load hook not implemented for plugin: {self.name}")

    def on_unload(self, app):
        """Called when the plugin is unloaded by the application."""
        log.info(f"on_unload hook not implemented for plugin: {self.name}")
