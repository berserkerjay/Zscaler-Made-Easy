import os
import sys

# Make the project root importable when pytest is run from anywhere.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# The UI token guards every API call from a browser; the test suite talks to
# the app directly, so it is off here. tests/test_ui_auth.py switches it on.
os.environ.setdefault("ZSCALER_UI_AUTH", "0")
