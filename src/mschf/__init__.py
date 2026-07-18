import atexit

_original_register = atexit.register

def custom_register(func, *args, **kwargs):
    try:
        func_name = getattr(func, '__name__', '')
        func_module = getattr(func, '__module__', '') or ''
        if func_name == 'unload' and 'pythonnet' in func_module:
            # Skip registering pythonnet's unload, preventing the Windows fatal access violation on shutdown!
            return func
    except Exception:
        pass
    return _original_register(func, *args, **kwargs)

atexit.register = custom_register

# Examples of valid version strings
# __version__ = '1.2.3.dev1'  # Development release 1
# __version__ = '1.2.3a1'     # Alpha Release 1
# __version__ = '1.2.3b1'     # Beta Release 1
# __version__ = '1.2.3rc1'    # RC Release 1
# __version__ = '1.2.3'       # Final Release
# __version__ = '1.2.3.post1' # Post Release 1

# Semver, pre-1.0: bump MINOR for features, PATCH for fixes. Keep in sync with
# pyproject.toml [tool.briefcase] version and add a CHANGELOG.md entry.
__version__ = '0.1.0'
