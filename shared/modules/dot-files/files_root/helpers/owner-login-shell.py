import pwd
import sys

try:
    shell = pwd.getpwnam("owner").pw_shell
except KeyError:
    raise SystemExit(70)

sys.stdout.write(shell)
