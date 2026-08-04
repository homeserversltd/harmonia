import pathlib
import subprocess
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
        self.assertIn("http://127.0.0.1:3014/api/v1/config/set", text)
        self.assertIn("--request POST", text)
        self.assertIn("--header 'Content-Type: application/json'", text)
        self.assertIn('"path":"tabs.portals"', text)
        self.assertIn('"name":"Element"', text)
        self.assertIn('"services":["matrix-synapse"]', text)
        self.assertIn('"port":8008', text)
        self.assertIn("first_missing_signal=caduceus-config-unreachable", text)


if __name__ == "__main__":
    unittest.main()
