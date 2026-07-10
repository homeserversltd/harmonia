import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MATRIX_CONVERGE = ROOT / "profiles/homeserver/modules/matrix/files_root/usr/local/libexec/harmonia-matrix-converge"


class MatrixConvergeScriptTests(unittest.TestCase):
    def test_apt_install_keeps_harmonia_managed_conffiles_noninteractive(self) -> None:
        text = MATRIX_CONVERGE.read_text(encoding="utf-8")
        self.assertIn("-o Dpkg::Options::=--force-confdef", text)
        self.assertIn("-o Dpkg::Options::=--force-confold", text)
        install_index = text.index("apt-get install -y")
        package_index = text.index("matrix-synapse-py3", install_index)
        confdef_index = text.index("--force-confdef", install_index)
        confold_index = text.index("--force-confold", install_index)
        self.assertLess(confdef_index, package_index)
        self.assertLess(confold_index, package_index)


if __name__ == "__main__":
    unittest.main()
