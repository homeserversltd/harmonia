# Hermes appearance module

Module id: `hermes-appearance`.

The module offers an owner interactable for the exact `homeserver-llc` skin
in already-existing Hermes homes. Review the offer, then run its displayed
command, `harmonia interactable run <offered-id>`, to adopt it. The run is the
explicit owner-authorized boundary: it backs up changed config through Hermes'
native backup primitive, installs the skin, and selects it only in the homes
named by that offer. Later owner skin choices are left alone. It does not
create Hermes homes. Newly created homes can be offered on a later module
refresh; already adopted homes are not offered again.

Discovery uses the Hermes installation selected by `HERMES_HOME` when set;
otherwise it uses the native home under the current account. When running as
root without `SUDO_USER`, discovery uses the standard `owner` account's passwd
home, never root's `HOME`; `SUDO_USER=root` is rejected. A missing native
installation is skipped without installing anything. If an installation is
present but its selected package-manager facts, environment, or Python source
are absent or invalid, discovery reports an error rather than guessing a
system Python. The adapter runs the Python selected by the installation facts
and imports the matching native source tree. Offer/maintenance discovery does
not change Hermes settings or installation files; only the explicit
interactable run performs the adoption.

For an isolated proof, point `HERMES_HOME` at the fixture's native Hermes root
and set `HERMES_PYTHON_SRC_ROOT` to its matching Hermes Python source tree.
Provide that fixture's native `installs/<source-root-digest>/facts.json` with
`packages.venv.environment` selecting an executable environment beneath that
install's `environments/` directory. Use the fixture's selected facts and
source; do not hard-code or invent an environment hash. Failures surface as
error signals. When a preflight or adoption failure writes a receipt, it has
`ok: false` and `first_missing_signal`; discovery failures such as invalid
native facts can surface directly without a receipt. Preserve the reported
signal when diagnosing either path.
