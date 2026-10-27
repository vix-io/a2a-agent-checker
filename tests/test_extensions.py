"""Extension declarations (spec 4.6)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from a2a_agent_checker.card import validate                             # noqa: E402
from test_checker import GOOD, URL, codes                               # noqa: E402


def with_ext(exts):
    return {**GOOD, "capabilities": {**GOOD["capabilities"], "extensions": exts}}


class Extensions(unittest.TestCase):

    def test_a_versioned_declaration_is_noted_and_nothing_else(self):
        f = validate(with_ext([{"uri": "https://stillopen.work/extensions/evidence/v1",
                                "required": False}]), URL)
        self.assertEqual([x.code for x in f].count("extension"), 1)
        self.assertNotIn("extension-unversioned", codes(f))
        self.assertNotIn("extension-malformed", codes(f))

    def test_an_unversioned_uri_is_pointed_out(self):
        f = validate(with_ext([{"uri": "https://example.com/ext/geo"}]), URL)
        self.assertIn("extension-unversioned", codes(f, "info"))

    def test_malformed_declarations_warn(self):
        for exts in ([{"description": "no uri"}], [{"uri": "geo"}], "x",
                     [{"uri": "https://e.com/x/v1", "required": "yes"}], [3]):
            self.assertIn("extension-malformed", codes(validate(with_ext(exts), URL), "warn"), exts)

    def test_no_extensions_no_findings(self):
        self.assertFalse([c for c in codes(validate(GOOD, URL)) if c.startswith("extension")])


if __name__ == "__main__":
    unittest.main()
