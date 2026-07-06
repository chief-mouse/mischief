import sys
import os
sys.path.insert(0, os.path.abspath('src'))

from mschf.storage import MSFStorage
from mschf.sandbox import execute_micro_app
import toga

# Ensure test_microapp.msf exists
if not os.path.exists('test_microapp.msf'):
    print("test_microapp.msf not found, running generator...")
    import test_microapp

print("Loading test_microapp.msf...")
db = MSFStorage('test_microapp.msf')

# 1. Check manifest
entry_point = db.get_manifest_item('entry_point')
print(f"Manifest entry point: {entry_point}")
assert entry_point == 'main_app', f"Expected 'main_app', got {entry_point}"

# 2. Get code
code_func = db.get_code(entry_point)
print(f"Code loaded: {code_func is not None}")
assert code_func is not None, "Failed to load code from database"

# 3. Execute in sandbox (dry-run without GUI main loop)
print("Executing micro-app in sandbox...")
workspace_dir = os.path.abspath('.')
# Create empty files to test host_api behavior
with open('test_host_api.msf', 'w') as f:
    f.write('dummy')

app_widget = execute_micro_app(code_func, workspace_dir, db, current_user_cn="CLTCM1", current_user_cert_pem="PEM_DATA")

# Clean up
if os.path.exists('test_host_api.msf'):
    os.remove('test_host_api.msf')

print(f"Returned widget type: {type(app_widget)}")
assert isinstance(app_widget, toga.Box), "Micro-app did not return a toga.Box widget"

print("Children of the returned box:")
for child in app_widget.children:
    print(f" - {type(child).__name__}: {getattr(child, 'text', getattr(child, 'value', ''))}")

print("\nAll automated integration checks passed successfully!")
