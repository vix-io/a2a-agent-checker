"""The --json output against its published schema. The validator is written
out for this one schema, so the test does not trust a library to agree with
what the schema says."""
import io
import json
import re
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from a2a_agent_checker import cli                                       # noqa: E402
from a2a_agent_checker.fetch import FetchRefused                        # noqa: E402
from test_checker import GOOD, URL, fake_fetcher, resp                  # noqa: E402

SCHEMA = json.loads(cli.schema_text())


def conforms(doc, schema=SCHEMA):
    item = schema["items"]
    fprops = item["properties"]["findings"]["items"]
    assert isinstance(doc, list)
    for rep in doc:
        assert set(rep) == set(item["required"]), set(rep) ^ set(item["required"])
        assert rep["verdict"] in item["properties"]["verdict"]["enum"]
        assert rep["agent"] is None or isinstance(rep["agent"], str)
        for f in rep["findings"]:
            assert set(f) == set(fprops["required"])
            assert f["level"] in fprops["properties"]["level"]["enum"]
            assert re.match(fprops["properties"]["code"]["pattern"], f["code"]), f["code"]


def run(argv, routes):
    out = io.StringIO()
    real = cli.check
    with mock.patch.object(cli, "check",
                           lambda t, probe=False: real(t, probe=probe, fetcher=fake_fetcher(routes))), \
            redirect_stdout(out):
        code = cli.main(argv)
    return code, out.getvalue()


class ReportSchema(unittest.TestCase):

    def test_pass_fail_and_odd_cards_all_conform(self):
        for body in (GOOD, {"name": "x"}, [1, 2], "just a string"):
            _, text = run(["example.com", "--json"], {("GET", URL): resp(URL, body)})
            conforms(json.loads(text))

    def test_an_unreachable_target_conforms(self):
        _, text = run(["example.com", "--json"],
                      {("GET", URL): FetchRefused("nope")})
        doc = json.loads(text)
        conforms(doc)
        self.assertIsNone(doc[0]["agent"])

    def test_a_list_card_does_not_crash_the_json_output(self):
        code, text = run(["example.com", "--json"], {("GET", URL): resp(URL, [1])})
        self.assertEqual(json.loads(text)[0]["verdict"], "fail")
        self.assertEqual(code, 1)

    def test_schema_flag_prints_the_schema_and_needs_no_target(self):
        code, text = run(["--schema"], {})
        self.assertEqual((code, json.loads(text)), (0, SCHEMA))

    def test_no_target_is_a_usage_error(self):
        with self.assertRaises(SystemExit) as e, redirect_stdout(io.StringIO()), \
                mock.patch("sys.stderr", io.StringIO()):
            cli.main([])
        self.assertEqual(e.exception.code, 2)

    def test_every_code_the_checker_emits_matches_the_pattern(self):
        pat = re.compile(SCHEMA["items"]["properties"]["findings"]["items"]
                         ["properties"]["code"]["pattern"])
        src = (Path(__file__).resolve().parents[1] / "src" / "a2a_agent_checker")
        codes = set()
        for p in src.glob("*.py"):
            codes |= set(re.findall(r'(?:fail|warn|info|Finding\("\w+",)\s*\(?\s*"([a-z0-9-]+)"',
                                    p.read_text()))
        self.assertGreater(len(codes), 15)
        self.assertEqual([c for c in codes if not pat.match(c)], [])


if __name__ == "__main__":
    unittest.main()
