# Ensures the repo root (containing the aos8_auditor package) is importable when
# running pytest without an editable install.
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
