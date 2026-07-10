import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
HEREDOC_START = re.compile(r"python3\s+-\s+<<'PY'")


def iter_shell_files():
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in {".git", "target"} for part in path.parts):
            continue
        if path.suffix in {".sh", ""} or path.name.endswith(".sh"):
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if "python3 - <<'PY'" in text:
                yield path, text


def extract_python_heredocs(path: pathlib.Path, text: str):
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        if HEREDOC_START.search(lines[index]):
            start_line = index + 1
            body = []
            index += 1
            while index < len(lines) and lines[index] != "PY":
                body.append(lines[index])
                index += 1
            if index >= len(lines):
                raise AssertionError(f"unterminated Python heredoc in {path}:{start_line}")
            yield start_line, "\n".join(body) + "\n"
        index += 1


class ShellPythonHeredocTests(unittest.TestCase):
    def test_embedded_python_heredocs_compile(self) -> None:
        checked = []
        for path, text in iter_shell_files():
            rel = path.relative_to(ROOT)
            for start_line, source in extract_python_heredocs(path, text):
                checked.append(f"{rel}:{start_line}")
                compile(source, f"{rel}:{start_line}", "exec")
        self.assertTrue(checked, "expected at least one python3 <<'PY' heredoc to be checked")


if __name__ == "__main__":
    unittest.main()
