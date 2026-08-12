use super::*;

pub(super) fn attest(
    appliance_log: &Path,
    receipt: &Receipt,
    declared_secrets: &[String],
) -> Result<(), String> {
    atoms::attest::attest(appliance_log, receipt, declared_secrets)
}
