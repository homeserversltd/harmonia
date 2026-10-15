import sys

output = sys.__stdout__
try:
    import contextlib
    import io

    sink = io.StringIO()
    with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        from pathlib import Path
        import yaml

        document = yaml.safe_load(Path(sys.argv[1]).read_text(encoding="utf-8"))
        server = document.get("server") if isinstance(document, dict) else None
        search = document.get("search") if isinstance(document, dict) else None
        if not isinstance(server, dict) or not isinstance(search, dict):
            raise ValueError
        if server.get("bind_address") != "127.0.0.1" or server.get("port") != 8888:
            raise ValueError
        formats = search.get("formats")
        if not isinstance(formats, list) or not {"html", "json"}.issubset(formats):
            raise ValueError
        secret = server.get("secret_key")
        secret_value = secret.strip() if isinstance(secret, str) else None
        if not secret_value or secret_value in {"__SEARXNG_BIRTH_SECRET__", "ultrasecretkey"}:
            raise ValueError
except BaseException:
    output.write("settings-invalid\n")
    raise SystemExit(1)

output.write("settings-valid\n")
raise SystemExit(0)
