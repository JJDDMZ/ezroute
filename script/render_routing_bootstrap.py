#!/usr/bin/env python3
"""Bundle the existing tested normalizer with the global bootstrap guard."""
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
normalizer = (root / 'routing/clash-usb-wifi.js').read_text()
guard = (root / 'routing/clash-bootstrap.js').read_text()
payload = ("// EZ Switch managed global routing v1\n"
           "const EZ_BOOTSTRAP_USB = 'en5';\n"
           "const ezSubscriptionNormalizer = (() => {\n" + normalizer +
           "\nreturn main;\n})();\n" + guard)
Path(sys.argv[1]).write_text(payload)
