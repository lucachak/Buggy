"""
test_discovery.py
=================
Test suite for modules/Reconnaissance/Discovery.py

  Unit tests   — all external calls (subprocess, network) are mocked.
  Integration  — hit the real Django REST API on http://127.0.0.1:8000
                 (marked with @pytest.mark.integration, skipped by default
                  when the server is unreachable).

Run unit tests only (fast, no network):
    pytest tests/test_discovery.py -v

Run everything including live API tests:
    pytest tests/test_discovery.py -v -m integration
"""

import os
import sys
import json
import types
import unittest
from unittest.mock import MagicMock, patch, mock_open

import pytest

# ── make sure the project root is on sys.path ──────────────────────────────
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from modules.Reconnaissance.Discovery import Discovery


# ═══════════════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════════════

LOCAL_TARGET = "http://127.0.0.1:8000/"


def _make_completed(stdout="", stderr="", returncode=0):
    """Build a fake subprocess.CompletedProcess."""
    cp = MagicMock()
    cp.stdout = stdout
    cp.stderr = stderr
    cp.returncode = returncode
    return cp


def _api_is_up() -> bool:
    """Return True if the Django dev server is reachable on port 8000."""
    import http.client
    try:
        conn = http.client.HTTPConnection("127.0.0.1", 8000, timeout=3)
        conn.request("GET", "/")
        resp = conn.getresponse()
        conn.close()
        return resp.status < 500
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════════════════
#  1. Discovery.__init__
# ═══════════════════════════════════════════════════════════════════════════

class TestDiscoveryInit(unittest.TestCase):

    def test_default_target(self):
        d = Discovery()
        self.assertEqual(d.get_target(), "http://localhost:8000/")

    def test_custom_target(self):
        d = Discovery(target=LOCAL_TARGET)
        self.assertEqual(d.get_target(), LOCAL_TARGET)

    def test_mutable_default_proxy_not_shared(self):
        """BUG-FIX CHECK: two instances must NOT share the same proxy dict."""
        d1 = Discovery()
        d2 = Discovery()
        self.assertIsNot(d1.get_proxy(), d2.get_proxy(),
                         "proxy dict must be a new object per instance")

    def test_info_retainers_empty_on_init(self):
        d = Discovery()
        self.assertEqual(d.get_subdomains(), [])
        self.assertEqual(d.get_endpoints(), [])
        self.assertEqual(d.get_pages(), [])
        self.assertEqual(d.get_params(), [])
        self.assertEqual(d.get_headers(), {})
        self.assertEqual(d.get_cookies(), {})
        self.assertIsNone(d.get_auth())


# ═══════════════════════════════════════════════════════════════════════════
#  2. _extract_domain
# ═══════════════════════════════════════════════════════════════════════════

class TestExtractDomain(unittest.TestCase):

    def test_strips_scheme_and_path(self):
        d = Discovery(target="http://example.com/some/path")
        self.assertEqual(d._extract_domain(), "example.com")

    def test_strips_www(self):
        d = Discovery(target="https://www.example.com/")
        self.assertEqual(d._extract_domain(), "example.com")

    def test_localhost_ip(self):
        d = Discovery(target="http://127.0.0.1:8000/api/")
        self.assertEqual(d._extract_domain(), "127.0.0.1")

    def test_localhost_name(self):
        d = Discovery(target="http://localhost:8000/")
        self.assertEqual(d._extract_domain(), "localhost")


# ═══════════════════════════════════════════════════════════════════════════
#  3. GetSummary
# ═══════════════════════════════════════════════════════════════════════════

class TestGetSummary(unittest.TestCase):

    def test_summary_has_all_keys(self):
        d = Discovery(target=LOCAL_TARGET)
        summary = d.GetSummary()
        expected = {
            "target", "domain", "subdomains", "live_ips",
            "origin_ips", "discovered_paths", "headers", "cookies", "auth",
        }
        self.assertEqual(set(summary.keys()), expected)

    def test_summary_reflects_state(self):
        d = Discovery(target=LOCAL_TARGET)
        d.set_subdomains(["api.local", "admin.local"])
        d.set_endpoints(["192.168.1.1"])
        summary = d.GetSummary()
        self.assertEqual(summary["subdomains"], ["api.local", "admin.local"])
        self.assertEqual(summary["live_ips"], ["192.168.1.1"])
        self.assertEqual(summary["target"], LOCAL_TARGET)

    def test_domain_for_local_target(self):
        d = Discovery(target=LOCAL_TARGET)
        self.assertEqual(d.GetSummary()["domain"], "127.0.0.1")


# ═══════════════════════════════════════════════════════════════════════════
#  4. GetSubdomains
# ═══════════════════════════════════════════════════════════════════════════

class TestGetSubdomains(unittest.TestCase):

    def test_returns_list(self):
        d = Discovery()
        self.assertIsInstance(d.GetSubdomains(), list)

    def test_returns_set_subdomains(self):
        d = Discovery()
        d.set_subdomains(["a.example.com", "b.example.com"])
        self.assertEqual(d.GetSubdomains(), ["a.example.com", "b.example.com"])


# ═══════════════════════════════════════════════════════════════════════════
#  5. run_subdomain_enum (mocked subprocess)
# ═══════════════════════════════════════════════════════════════════════════

class TestRunSubdomainEnum(unittest.TestCase):

    @patch("modules.Reconnaissance.Discovery.subprocess.run")
    def test_five_commands_are_called(self, mock_run):
        mock_run.return_value = _make_completed()
        with patch("builtins.open", mock_open(read_data="sub1.example.com\nsub2.example.com\n")):
            d = Discovery(target="http://example.com/")
            d.run_subdomain_enum()
        self.assertEqual(mock_run.call_count, 5)

    @patch("modules.Reconnaissance.Discovery.subprocess.run")
    def test_subdomains_stored(self, mock_run):
        mock_run.return_value = _make_completed()
        with patch("builtins.open", mock_open(read_data="alpha.example.com\nbeta.example.com\n")):
            d = Discovery(target="http://example.com/")
            d.run_subdomain_enum()
        self.assertIn("alpha.example.com", d.get_subdomains())
        self.assertIn("beta.example.com", d.get_subdomains())

    @patch("modules.Reconnaissance.Discovery.subprocess.run")
    def test_missing_file_does_not_crash(self, mock_run):
        mock_run.return_value = _make_completed()
        with patch("builtins.open", side_effect=FileNotFoundError):
            d = Discovery(target="http://example.com/")
            d.run_subdomain_enum()   # must NOT raise
        self.assertEqual(d.get_subdomains(), [])


# ═══════════════════════════════════════════════════════════════════════════
#  6. run_dns_resolution (mocked subprocess)
# ═══════════════════════════════════════════════════════════════════════════

class TestRunDnsResolution(unittest.TestCase):

    @patch("modules.Reconnaissance.Discovery.subprocess.run")
    def test_live_ips_stored(self, mock_run):
        mock_run.return_value = _make_completed(stdout="93.184.216.34")
        with patch("builtins.open", mock_open(read_data="10.0.0.1\n10.0.0.2\n")):
            d = Discovery(target="http://example.com/")
            d.run_dns_resolution()
        self.assertIn("10.0.0.1", d.get_endpoints())

    @patch("modules.Reconnaissance.Discovery.subprocess.run")
    def test_missing_live_ips_does_not_crash(self, mock_run):
        mock_run.return_value = _make_completed()
        with patch("builtins.open", side_effect=FileNotFoundError):
            d = Discovery(target="http://example.com/")
            d.run_dns_resolution()   # must NOT raise

    @patch("modules.Reconnaissance.Discovery.subprocess.run")
    def test_dns_resolution_commands_executed(self, mock_run):
        mock_run.return_value = _make_completed()
        with patch("builtins.open", mock_open(read_data="")):
            d = Discovery(target="http://mytarget.com/")
            d.run_dns_resolution()
        # Ensure dnsx is called
        calls_str = " ".join(str(c) for c in mock_run.call_args_list)
        self.assertIn("dnsx", calls_str)


# ═══════════════════════════════════════════════════════════════════════════
#  7. run_origin_ip_discovery (mocked subprocess)
# ═══════════════════════════════════════════════════════════════════════════

class TestRunOriginIpDiscovery(unittest.TestCase):

    @patch("modules.Reconnaissance.Discovery.subprocess.run")
    def test_ips_extracted_from_stdout(self, mock_run):
        mock_run.return_value = _make_completed(stdout="Server at 93.184.216.34 found")
        d = Discovery(target="http://example.com/")
        d.run_origin_ip_discovery()
        self.assertIn("93.184.216.34", d.get_pages())

    @patch("modules.Reconnaissance.Discovery.subprocess.run")
    def test_no_ips_gives_empty_pages(self, mock_run):
        mock_run.return_value = _make_completed(stdout="nothing here")
        d = Discovery(target="http://example.com/")
        d.run_origin_ip_discovery()
        self.assertEqual(d.get_pages(), [])

    @patch("modules.Reconnaissance.Discovery.subprocess.run")
    def test_duplicate_ips_deduplicated(self, mock_run):
        mock_run.return_value = _make_completed(stdout="1.2.3.4 and 1.2.3.4 again")
        d = Discovery(target="http://example.com/")
        d.run_origin_ip_discovery()
        self.assertEqual(d.get_pages().count("1.2.3.4"), 1)


# ═══════════════════════════════════════════════════════════════════════════
#  8. run_dir_busting — mutable default sentinel check
# ═══════════════════════════════════════════════════════════════════════════

class TestRunDirBustingDefaults(unittest.TestCase):

    def test_allowed_status_default_is_none_sentinel(self):
        """BUG-FIX CHECK: allowed_status default must be None, not a literal set."""
        import inspect
        d = Discovery()
        sig = inspect.signature(d.run_dir_busting)
        default = sig.parameters["allowed_status"].default
        self.assertIsNone(default,
            "allowed_status default must be None (sentinel), not a mutable set literal")

    def test_exec_allowed_status_default_is_none_sentinel(self):
        import inspect
        d = Discovery()
        sig = inspect.signature(d.exec)
        default = sig.parameters["allowed_status"].default
        self.assertIsNone(default,
            "exec allowed_status default must be None (sentinel)")


# ═══════════════════════════════════════════════════════════════════════════
#  9. Getters / Setters round-trip
# ═══════════════════════════════════════════════════════════════════════════

class TestGettersSetters(unittest.TestCase):

    def setUp(self):
        self.d = Discovery(target=LOCAL_TARGET)

    def test_target_roundtrip(self):
        self.d.set_target("http://newhost.com/")
        self.assertEqual(self.d.get_target(), "http://newhost.com/")

    def test_user_agent_roundtrip(self):
        self.d.set_user_agent("TestAgent/1.0")
        self.assertEqual(self.d.get_user_agent(), "TestAgent/1.0")

    def test_proxy_roundtrip(self):
        proxy = {"http": "http://proxy:8080"}
        self.d.set_proxy(proxy)
        self.assertEqual(self.d.get_proxy(), proxy)

    def test_subdomains_roundtrip(self):
        self.d.set_subdomains(["a.com", "b.com"])
        self.assertEqual(self.d.get_subdomains(), ["a.com", "b.com"])

    def test_endpoints_roundtrip(self):
        self.d.set_endpoints(["1.2.3.4"])
        self.assertEqual(self.d.get_endpoints(), ["1.2.3.4"])

    def test_cookies_roundtrip(self):
        self.d.set_cookies({"session": "abc"})
        self.assertEqual(self.d.get_cookies(), {"session": "abc"})

    def test_auth_roundtrip(self):
        self.d.set_auth(("user", "pass"))
        self.assertEqual(self.d.get_auth(), ("user", "pass"))



# ═══════════════════════════════════════════════════════════════════════════
#  10. INTEGRATION — live Django REST API on 127.0.0.1:8000
#      Automatically skipped when the server is not reachable.
#      Run explicitly with:  pytest tests/test_discovery.py -v -m integration
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.integration
@pytest.mark.skipif(not _api_is_up(), reason="Django API not reachable on 127.0.0.1:8000")
class TestIntegrationLocalAPI:

    def test_api_root_responds(self):
        """Sanity: the API root must return a non-5xx status."""
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", 8000, timeout=5)
        conn.request("GET", "/", headers={"Accept": "application/json"})
        resp = conn.getresponse()
        conn.close()
        assert resp.status < 500, f"Unexpected status from API root: {resp.status}"

    def test_extract_domain_on_localhost(self):
        d = Discovery(target=LOCAL_TARGET)
        assert d._extract_domain() == "127.0.0.1"

    def test_get_summary_structure(self):
        d = Discovery(target=LOCAL_TARGET)
        summary = d.GetSummary()
        assert summary["target"] == LOCAL_TARGET
        assert summary["domain"] == "127.0.0.1"
        assert isinstance(summary["subdomains"], list)
        assert isinstance(summary["discovered_paths"], list)

    def test_dir_busting_against_local_api(self):
        """
        Dir-busting against localhost:8000 with a small inline wordlist.
        Verifies the scan runs end-to-end and stores results correctly.
        """
        dirpy_wl_dir = os.path.join(
            ROOT, "modules", "Reconnaissance", "Dirpy", "wordlist"
        )
        wl_path = os.path.join(dirpy_wl_dir, "_test_wl.txt")
        try:
            with open(wl_path, "w") as f:
                # Common Django paths — at least one should hit
                f.write("api\nadmin\nlogin\nproducts\nusers\nApi\n")

            d = Discovery(target=LOCAL_TARGET)
            d.run_dir_busting(
                wordlist="_test_wl.txt",
                threads=5,
                allowed_status={200, 301, 302, 403},
                recursive=False,
            )

            params = d.get_params()
            assert isinstance(params, list)
            print(f"\n[integration] discovered paths: {params}")

            # Summary must reflect the busted paths
            summary = d.GetSummary()
            assert summary["discovered_paths"] == params
        finally:
            if os.path.exists(wl_path):
                os.remove(wl_path)

    def test_dir_busting_recursive_mode(self):
        """Recursive dir-busting must not crash and must still return a list."""
        dirpy_wl_dir = os.path.join(
            ROOT, "modules", "Reconnaissance", "Dirpy", "wordlist"
        )
        wl_path = os.path.join(dirpy_wl_dir, "_test_recursive_wl.txt")
        try:
            with open(wl_path, "w") as f:
                f.write("api\nadmin\n")

            d = Discovery(target=LOCAL_TARGET)
            d.run_dir_busting(
                wordlist="_test_recursive_wl.txt",
                threads=5,
                recursive=True,
            )
            assert isinstance(d.get_params(), list)
        finally:
            if os.path.exists(wl_path):
                os.remove(wl_path)

    def test_save_report_integration(self):
        """SaveReport must create both .txt and .json files with valid data only."""
        import json as _json
        import tempfile

        dirpy_wl_dir = os.path.join(
            ROOT, "modules", "Reconnaissance", "Dirpy", "wordlist"
        )
        wl_path = os.path.join(dirpy_wl_dir, "_test_report_wl.txt")
        out_dir  = tempfile.mkdtemp()
        try:
            with open(wl_path, "w") as f:
                f.write("api\nadmin\nlogin\nproducts\n")

            d = Discovery(target=LOCAL_TARGET)
            d.run_dir_busting(wordlist="_test_report_wl.txt", threads=5)

            txt_path, json_path = d.SaveReport(output_dir=out_dir)

            # both files must exist
            assert os.path.exists(txt_path),  "TXT report not created"
            assert os.path.exists(json_path), "JSON report not created"

            # JSON must be valid and contain meta + results
            with open(json_path) as f:
                data = _json.load(f)
            assert data["meta"]["target"]  == LOCAL_TARGET
            assert data["meta"]["domain"]  == "127.0.0.1"
            assert "results" in data

            # Empty fields must NOT appear in results
            results = data["results"]
            for key, val in results.items():
                if isinstance(val, list):
                    assert len(val) > 0, f"Empty list for '{key}' should have been filtered"
                elif isinstance(val, dict):
                    assert len(val) > 0, f"Empty dict for '{key}' should have been filtered"
                else:
                    assert val is not None and str(val).strip(), \
                        f"Empty value for '{key}' should have been filtered"

            # TXT must contain the domain header
            with open(txt_path) as f:
                txt = f.read()
            assert "127.0.0.1" in txt
            assert "BUGGY RECON REPORT" in txt

            print(f"\n[integration] TXT  → {txt_path}")
            print(f"[integration] JSON → {json_path}")
        finally:
            if os.path.exists(wl_path):
                os.remove(wl_path)


# ═══════════════════════════════════════════════════════════════════════════
#  11. Unit tests — SaveReport (no network, uses tmp dir)
# ═══════════════════════════════════════════════════════════════════════════

class TestSaveReport(unittest.TestCase):

    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_creates_both_files(self):
        d = Discovery(target=LOCAL_TARGET)
        d.set_subdomains(["api.example.com"])
        d.set_params(["http://127.0.0.1:8000/api"])

        txt, jsn = d.SaveReport(output_dir=self.tmp)
        self.assertTrue(os.path.exists(txt),  "TXT not created")
        self.assertTrue(os.path.exists(jsn), "JSON not created")

    def test_json_structure(self):
        d = Discovery(target=LOCAL_TARGET)
        d.set_subdomains(["sub.example.com"])
        d.set_endpoints(["10.0.0.1"])

        _, jsn = d.SaveReport(output_dir=self.tmp)
        with open(jsn) as f:
            data = json.load(f)

        self.assertIn("meta",    data)
        self.assertIn("results", data)
        self.assertEqual(data["meta"]["domain"], "127.0.0.1")
        self.assertIn("subdomains", data["results"])
        self.assertIn("live_ips",   data["results"])

    def test_empty_fields_filtered_out(self):
        """Fields with no data must NOT appear in the JSON results."""
        d = Discovery(target=LOCAL_TARGET)
        # only set subdomains; everything else stays empty
        d.set_subdomains(["only.sub.com"])

        _, jsn = d.SaveReport(output_dir=self.tmp)
        with open(jsn) as f:
            data = json.load(f)

        results = data["results"]
        self.assertIn("subdomains",       results)
        self.assertNotIn("live_ips",       results, "empty list should be filtered")
        self.assertNotIn("origin_ips",     results, "empty list should be filtered")
        self.assertNotIn("discovered_paths", results, "empty list should be filtered")
        self.assertNotIn("headers",        results, "empty dict should be filtered")
        self.assertNotIn("cookies",        results, "empty dict should be filtered")

    def test_txt_contains_section_headers(self):
        d = Discovery(target=LOCAL_TARGET)
        d.set_subdomains(["sub.example.com"])
        d.set_params(["http://target.com/admin"])

        txt, _ = d.SaveReport(output_dir=self.tmp)
        with open(txt) as f:
            content = f.read()

        self.assertIn("BUGGY RECON REPORT",         content)
        self.assertIn("SUBDOMAINS",                  content)
        self.assertIn("DISCOVERED PATHS",            content)
        self.assertIn("sub.example.com",             content)
        self.assertIn("http://target.com/admin",     content)

    def test_filename_contains_domain_and_timestamp(self):
        d = Discovery(target="http://testdomain.com/")
        d.set_subdomains(["x.testdomain.com"])

        txt, jsn = d.SaveReport(output_dir=self.tmp)
        self.assertIn("testdomain.com", os.path.basename(txt))
        self.assertIn("testdomain.com", os.path.basename(jsn))

    def test_output_dir_is_created_if_missing(self):
        import shutil
        new_dir = os.path.join(self.tmp, "nested", "reports")
        shutil.rmtree(new_dir, ignore_errors=True)

        d = Discovery(target=LOCAL_TARGET)
        d.set_subdomains(["x.example.com"])
        d.SaveReport(output_dir=new_dir)

        self.assertTrue(os.path.isdir(new_dir))


# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    unittest.main(verbosity=2)
