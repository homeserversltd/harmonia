import json
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MATRIX_CONVERGE = ROOT / "profiles/homeserver/modules/matrix/files_root/usr/local/libexec/harmonia-matrix-converge"


class MatrixConvergeScriptTests(unittest.TestCase):
    def script_text(self) -> str:
        return MATRIX_CONVERGE.read_text(encoding="utf-8")


    def test_harmonia_converger_does_not_install_birth_owned_packages(self) -> None:
        text = self.script_text()
        self.assertNotIn("apt-get install", text)
        self.assertNotIn("apt-get update", text)

    def test_birth_secrets_are_group_readable_for_synapse_config_loader(self) -> None:
        text = self.script_text()
        self.assertIn("chown root:matrix-synapse \"$tmp\"", text)
        self.assertIn("chmod 0640 \"$tmp\"", text)
        self.assertIn("chown root:matrix-synapse \"$secrets\"", text)
        self.assertIn("chmod 0640 \"$secrets\"", text)
        self.assertNotIn("chmod 0600 \"$tmp\"", text)
        self.assertNotIn("chmod 0600 \"$secrets\"", text)

    def test_postgres_peer_admission_precedes_local_scram_catchall_and_reloads(self) -> None:
        text = self.script_text()
        self.assertIn("ensure_postgres_peer_admission()", text)
        self.assertIn("desired='local   synapse         matrix-synapse                          peer'", text)
        self.assertIn('$1 == "local" && $2 == "all" && $3 == "all" && $4 == "scram-sha-256"', text)
        self.assertIn("SELECT pg_reload_conf();", text)
        self.assertLess(text.index("--file=/usr/share/harmonia/matrix/postgres.sql"), text.index("\nensure_postgres_peer_admission\n"))

    def test_unbound_conf_d_include_is_ensured_before_active_reload_only(self) -> None:
        text = self.script_text()
        self.assertIn("ensure_unbound_conf_d_include()", text)
        self.assertIn('include=\'include-toplevel: "/etc/unbound/unbound.conf.d/*.conf"\'', text)
        unbound_reload = "reload_when_material_changed unbound unbound.service"
        self.assertIn(unbound_reload, text)
        self.assertNotIn("systemctl restart unbound.service", text)
        self.assertLess(text.index("ensure_unbound_conf_d_include"), text.index("unbound-checkconf"))
        self.assertLess(text.index("unbound-checkconf"), text.index(unbound_reload))

    def test_matrix_portal_is_delegated_to_caduceus(self) -> None:
        text = self.script_text()
        self.assertNotIn("/etc/homeserver", text)
        self.assertIn("http://127.0.0.1:3014/api/v1/config/show", text)
        self.assertIn("http://127.0.0.1:3014/api/v1/config/set", text)
        self.assertIn("--request POST", text)
        self.assertIn("--header 'Content-Type: application/json'", text)
        self.assertIn("tabs.portals.data.portals", text)
        self.assertIn("tabs.portals.visibility.elements", text)
        self.assertIn("first_missing_signal=caduceus-config-unreachable", text)

    def test_matrix_portal_merge_preserves_preexisting_non_element_portal(self) -> None:
        text = self.script_text()
        merge_program = text.split("<<'PY'\n", 1)[1].split("\nPY\nthen", 1)[0]
        jellyfin = {
            "name": "Jellyfin",
            "description": "Preserve this exact portal record.",
            "services": ["jellyfin"],
            "type": "systemd",
            "port": 8096,
            "localURL": "https://jellyfin.home.arpa",
        }
        document = {
            "tabs": {
                "portals": {
                    "data": {"portals": [jellyfin, {"name": "eLeMeNt", "stale": True}]},
                    "visibility": {"elements": {"element": True, "Jellyfin": True}},
                }
            }
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = pathlib.Path(tmpdir)
            source = tmp / "document.json"
            portals = tmp / "portals.json"
            elements = tmp / "elements.json"
            source.write_text(json.dumps({"document": document}), encoding="utf-8")
            subprocess.run(
                ["python3", "-c", merge_program, str(source), str(portals), str(elements)],
                check=True,
            )
            portals_payload = json.loads(portals.read_text(encoding="utf-8"))
            elements_payload = json.loads(elements.read_text(encoding="utf-8"))
            first_portals_payload = portals.read_bytes()
            first_elements_payload = elements.read_bytes()
            subprocess.run(
                ["python3", "-c", merge_program, str(source), str(portals), str(elements)],
                check=True,
            )
            self.assertEqual(portals.read_bytes(), first_portals_payload)
            self.assertEqual(elements.read_bytes(), first_elements_payload)

        self.assertEqual(portals_payload["path"], "tabs.portals.data.portals")
        self.assertEqual(portals_payload["value"][0], jellyfin)
        self.assertEqual(portals_payload["value"][1]["name"], "Element")
        self.assertEqual(elements_payload["path"], "tabs.portals.visibility.elements")
        self.assertNotIn("element", elements_payload["value"])
        self.assertTrue(elements_payload["value"]["Element"])
        self.assertTrue(elements_payload["value"]["Jellyfin"])


if __name__ == "__main__":
    unittest.main()
