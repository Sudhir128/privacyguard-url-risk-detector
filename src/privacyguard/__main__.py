"""Allow running the package as ``python -m privacyguard``."""

import sys

from privacyguard.main import cli

sys.exit(cli())
