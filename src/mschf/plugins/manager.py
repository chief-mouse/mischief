import logging
import importlib

log = logging.getLogger(__name__)

class PluginManager:
    def __init__(self, app):
        self.app = app
        self.plugins = {}

    def load_plugin(self, module_path, class_name):
        try:
            log.info(f"Loading plugin: {module_path}.{class_name}")
            mod = importlib.import_module(module_path)
            cls = getattr(mod, class_name)
            plugin = cls()
            if plugin.enabled:
                plugin.on_load(self.app)
                self.plugins[plugin.name] = plugin
                log.info(f"Successfully loaded plugin: {plugin.name}")
            else:
                log.info(f"Plugin {plugin.name} is disabled.")
        except Exception as e:
            log.error(f"Failed to load plugin {module_path}.{class_name}: {e}", exc_info=True)

    def load_all(self):
        # Discovers and loads built-in premium plugins
        self.load_plugin("mschf.plugins.auth", "AuthPlugin")

    def unload_all(self):
        for name, plugin in list(self.plugins.items()):
            try:
                plugin.on_unload(self.app)
                log.info(f"Successfully unloaded plugin: {name}")
            except Exception as e:
                log.error(f"Failed to unload plugin {name}: {e}")
        self.plugins.clear()
