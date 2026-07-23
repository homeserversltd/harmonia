import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MATRIX_CONVERGE = ROOT / "profiles/homeserver/modules/matrix/files_root/usr/local/libexec/harmonia-matrix-converge"


class MatrixConvergeScriptTests(unittest.TestCase):
    def script_text(self) -> str:
        return MATRIX_CONVERGE.read_text(encoding="utf-8")

    def config_converger_source(self, config_path: pathlib.Path) -> str:
        text = self.script_text()
        source = text.split("python3 - <<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        return source.replace("Path('/etc/homeserver/config.json')", f"Path({str(config_path)!r})")

    def run_as_root(self, source: str) -> None:
        subprocess.run(["sudo", "-n", sys.executable, "-c", source], check=True)

    def require_noninteractive_sudo(self) -> None:
        if subprocess.run(["sudo", "-n", "true"], check=False).returncode != 0:
            self.skipTest("fixture ownership proof requires noninteractive sudo")

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
        self.assertIn("systemctl reload unbound.service", text)
        self.assertNotIn("systemctl restart unbound.service", text)
        self.assertLess(text.index("ensure_unbound_conf_d_include"), text.index("unbound-checkconf"))
        self.assertLess(text.index("unbound-checkconf"), text.index("systemctl reload unbound.service"))

    def test_matrix_portal_uses_the_directory_seated_new_stack_config(self) -> None:
        text = self.script_text()
        self.assertIn("[ -d /etc/homeserver ] || install -d -o root -g root -m 0755 /etc/homeserver", text)
        self.assertNotIn("\ninstall -d -o root -g root -m 0755 /etc/homeserver\n", text)
        self.assertIn("Path('/etc/homeserver/config.json')", text)
        self.assertNotIn("Path('/etc/homeserver.json')", text)
        self.assertIn("elements['Element'] = True", text)
        self.assertIn("elements.pop('element', None)", text)
        self.assertIn("'name': 'Element'", text)
        self.assertIn("'services': ['matrix-synapse']", text)
        self.assertIn("'port': 8008", text)
        self.assertNotIn("'owningUnits'", text)
        self.assertNotIn("'status'", text)
        portal_entry = text.split("entry = {", 1)[1].split("for index, item", 1)[0]
        self.assertNotIn("nginx", portal_entry)

    def test_config_convergence_preserves_shared_ownership_and_skips_identical_write(self) -> None:
        self.require_noninteractive_sudo()
        with tempfile.TemporaryDirectory() as tmpdir:
            homeserver = pathlib.Path(tmpdir) / "etc" / "homeserver"
            homeserver.mkdir(parents=True)
            config = homeserver / "config.json"
            source = self.config_converger_source(config)

            self.run_as_root(source)
            shared_gid = os.getgid()
            self.run_as_root(
                "import os; "
                f"os.chown({str(homeserver)!r}, 0, {shared_gid}); "
                f"os.chmod({str(homeserver)!r}, 0o775); "
                f"os.chown({str(config)!r}, 0, {shared_gid}); "
                f"os.chmod({str(config)!r}, 0o640)"
            )

            before = config.stat()
            directory_before = homeserver.stat()
            self.run_as_root(source)
            after = config.stat()
            directory_after = homeserver.stat()
            self.assertEqual(after.st_gid, before.st_gid)
            self.assertEqual(directory_after.st_gid, directory_before.st_gid)
            self.assertEqual(after.st_ino, before.st_ino)
            self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)
            self.assertEqual(after.st_mode & 0o777, before.st_mode & 0o777)

            incorrect_data = {"tabs": {"portals": {"visibility": {"elements": {"element": True}}}}}
            self.run_as_root(
                "import json; from pathlib import Path; "
                f"Path({str(config)!r}).write_text({json.dumps(incorrect_data)!r}, encoding='utf-8')"
            )
            incorrect = config.stat()
            self.run_as_root(source)
            corrected = config.stat()
            data = json.loads(config.read_text(encoding="utf-8"))
            self.assertNotEqual(corrected.st_ino, incorrect.st_ino)
            self.assertEqual(corrected.st_gid, shared_gid)
            self.assertEqual(corrected.st_mode & 0o777, 0o640)
            self.assertTrue(data["tabs"]["portals"]["visibility"]["elements"]["Element"])
            self.assertNotIn("element", data["tabs"]["portals"]["visibility"]["elements"])
            self.assertEqual(data["tabs"]["portals"]["data"]["portals"][0]["name"], "Element")


if __name__ == "__main__":
    unittest.main()
