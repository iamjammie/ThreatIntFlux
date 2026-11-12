"""Checks on the console page and the committed fixture feed.

* The page's inline JavaScript must parse (run with Node when available).
* The committed fixture feed must pass the same validator the collector output goes through.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import threatintflux_validate as tv  # noqa: E402


def _inline_script():
    html = open(os.path.join(ROOT, "index.html"), encoding="utf-8").read()
    blocks = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, flags=re.S)
    assert blocks, "no inline <script> found in index.html"
    return max(blocks, key=len)


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_inline_javascript_parses():
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(_inline_script())
        path = f.name
    try:
        res = subprocess.run(["node", "--check", path], capture_output=True, text=True)
        assert res.returncode == 0, res.stderr
    finally:
        os.unlink(path)


def test_fixture_feed_is_valid():
    path = os.path.join(ROOT, "tests", "fixtures", "feed_sample.json")
    with open(path, encoding="utf-8") as f:
        feed = json.load(f)
    errors, _ = tv.validate(feed)
    assert errors == []
    assert feed["mode"] == "sample"
    assert all(i["synthetic"] for i in feed["items"]), "fixture must be clearly synthetic"


def test_every_collector_source_is_listed_in_console():
    """The validator joins source status to items by display name, so the names must match exactly."""
    import threatintflux_collector as tc
    html = open(os.path.join(ROOT, "index.html"), encoding="utf-8").read()
    block = html[html.index("const SOURCES = ["):html.index("];", html.index("const SOURCES = ["))]
    console_names = set(re.findall(r"name:'([^']+)'", block))
    collector_names = {name for name, _ in tc.SOURCES} | {tc.MITRE_SOURCE}
    missing = collector_names - console_names
    assert not missing, f"collector sources missing from console SOURCES: {missing}"

