import sys
from pathlib import Path

# Add src directory to Python path for Vercel Serverless Function deployment
root_dir = Path(__file__).resolve().parent.parent
src_dir = root_dir / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from privacyguard.api.app import app
