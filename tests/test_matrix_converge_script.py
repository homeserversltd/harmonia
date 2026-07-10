import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MATRIX_CONVERGE = ROOT / "profiles/homeserver/modules/matrix/files_root/usr/local/libexec/harmonia-matrix-converge"


class MatrixConvergeScriptTests(unittest.TestCase):
    def script_text(self) -> str:
        return MATRIX_CONVERGE.read_text(encoding="utf-8")

    def test_apt_install_keeps_harmonia_managed_conffiles_noninteractive(self) -> None:
        text = self.script_text()
        self.assertIn("-o Dpkg::Options::=--force-confdef", text)
        self.assertIn("-o Dpkg::Options::=--force-confold", text)
        install_index = text.index("apt-get install -y")
        package_index = text.index("matrix-synapse-py3", install_index)
        confdef_index = text.index("--force-confdef", install_index)
        confold_index = text.index("--force-confold", install_index)
        self.assertLess(confdef_index, package_index)
        self.assertLess(confold_index, package_index)

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
        self.assertIn("systemctl reload unbound.service", text)
        self.assertNotIn("systemctl restart unbound.service", text)
        self.assertLess(text.index("ensure_unbound_conf_d_include"), text.index("unbound-checkconf"))
        self.assertLess(text.index("unbound-checkconf"), text.index("systemctl reload unbound.service"))


if __name__ == "__main__":
    unittest.main()
