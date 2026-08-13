#[path = "backfill-files/index.rs"]
pub(crate) mod backfill_files;
#[path = "compare/index.rs"]
pub(crate) mod compare;
#[path = "install-packages/index.rs"]
pub(crate) mod install_packages;
#[path = "propose-edits/index.rs"]
pub(crate) mod propose_edits;
#[path = "pull-source/index.rs"]
pub(crate) mod pull_source;
#[path = "ratchet-binaries/index.rs"]
pub(crate) mod ratchet_binaries;
#[path = "renew-self/index.rs"]
pub(crate) mod renew_self;
#[path = "report-home/index.rs"]
pub(crate) mod report_home;
#[path = "restart-services/index.rs"]
pub(crate) mod restart_services;
#[path = "stage-profile/index.rs"]
pub(crate) mod stage_profile;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Band {
    RenewSelf,
    PullSource,
    StageProfile,
    Compare,
    InstallPackages,
    RatchetBinaries,
    RestartServices,
    BackfillFiles,
    ProposeEdits,
    ReportHome,
}

pub(crate) fn walk(mut enter: impl FnMut(Band) -> Result<(), String>) -> Result<(), String> {
    renew_self::enter(&mut enter)?;
    pull_source::enter(&mut enter)?;
    stage_profile::enter(&mut enter)?;
    compare::enter(&mut enter)?;
    install_packages::enter(&mut enter)?;
    ratchet_binaries::enter(&mut enter)?;
    restart_services::enter(&mut enter)?;
    backfill_files::enter(&mut enter)?;
    propose_edits::enter(&mut enter)?;
    report_home::enter(&mut enter)?;
    Ok(())
}
