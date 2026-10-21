//! Diff-authorized subtree promotion, atomic exchange, rollback, and service restart.
use crate::atoms::ask::mem0_maintenance as ask;
use crate::atoms::comparison::ActionAuthorization;
use crate::atoms::r#do::InvocationKey;
use crate::atoms::r#do::change_unit::{unit_change_scoped, UnitVerb};
use crate::tools::mem0_maintenance::{Output, Request};
use crate::SoftwareApplyAuthorization;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const PREDECESSOR_MARKER: &str = ".mem0-maintenance-predecessor-owner";
const TREE_LIST_ENTRY_LIMIT: usize = 8192;
const TREE_LIST_TOTAL_LIMIT: u64 = 128 * 1024 * 1024;
const FILE_LIMIT: u64 = 128 * 1024 * 1024;
const TREE_BYTES_LIMIT: u64 = 512 * 1024 * 1024;

#[derive(Clone, Copy)]
enum TreeMode {
    Canonical,
    Legacy,
}

#[derive(Debug, Clone)]
pub(crate) struct Movement {
    pub(crate) ok: bool,
    pub(crate) changed: bool,
    pub(crate) status: String,
    pub(crate) restart: Option<String>,
    pub(crate) health: Option<String>,
    pub(crate) runtime_identity: Option<String>,
    pub(crate) identity_evidence: Option<String>,
    pub(crate) process_main_pid: Option<u32>,
    pub(crate) process_start_monotonic_usec: Option<String>,
    pub(crate) process_boot_id: Option<String>,
    pub(crate) process_cwd_binding: Option<bool>,
    pub(crate) process_cmdline_binding: Option<bool>,
    pub(crate) promotion_boot_id: Option<String>,
    pub(crate) promotion_monotonic_usec: Option<u64>,
    pub(crate) first_missing_signal: Option<String>,
    pub(crate) duration_ms: u128,
}

pub(crate) fn predecessor_path(request: &Request) -> PathBuf {
    let root = &request.app_root;
    let name = root.file_name().and_then(|name| name.to_str()).unwrap_or("app");
    root.with_file_name(format!(".{name}.mem0-maintenance-predecessor"))
}

pub(crate) fn promote(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    software: &SoftwareApplyAuthorization,
    request: &Request,
    observed: &ask::Observation,
) -> Result<Movement, String> {
    let started = std::time::Instant::now();
    let result = promote_inner(authorization, invocation, software, request, observed);
    match result {
        Ok(mut movement) => {
            movement.duration_ms = started.elapsed().as_millis();
            Ok(movement)
        }
        Err(error) => Ok(Movement::failure(&error, started.elapsed().as_millis())),
    }
}

fn promote_inner(
    authorization: &ActionAuthorization, invocation: &InvocationKey, _software: &SoftwareApplyAuthorization,
    request: &Request, observed: &ask::Observation,
) -> Result<Movement,String> {
    let _lock=ask::lock_app_root(request,true)?;
    let current=ask::observe_unlocked(request)?;
    if !current.changed&&current.first_missing_signal.is_none(){return Ok(Movement::current());}
    if current.source_head!=observed.source_head||current.source_tree!=observed.source_tree||current.recorded_head!=observed.recorded_head||current.recorded_tree!=observed.recorded_tree||current.target_device!=observed.target_device||current.target_inode!=observed.target_inode||current.app_root_device!=observed.app_root_device||current.app_root_inode!=observed.app_root_inode{return Err("mem0-maintenance-preimage-changed-before-act".into());}
    if current.first_missing_signal.as_deref()==Some("managed-subtree-absent"){return Err("managed-subtree-absent".into());}
    let unit=request.unit.as_deref().ok_or("mem0-maintenance-unit-required-before-changed-act")?;
    if request.health_url.is_none(){return Err("mem0-maintenance-health-url-required-before-changed-act".into());}
    if request.identity_json_pointer.is_none(){return Err("process-source-identity-pointer-not-configured".into());}
    let owner=ask::validate_owner(request)?;let app_root=ask::canonical_directory(&request.app_root,"app-root")?;let source_root=ask::canonical_directory(&request.source_root,"source-root")?;
    if source_root.starts_with(&app_root)||app_root.starts_with(&source_root){return Err("mem0-maintenance-source-and-app-roots-must-be-disjoint".into());}
    let target=app_root.join(&request.subtree);validate_target_parent(&app_root,&request.subtree,owner)?;validate_managed_root(&app_root,&request.subtree,owner,false,TreeMode::Legacy)?;
    let target_meta=fs::symlink_metadata(&target).map_err(|error|format!("mem0-maintenance-target-recheck-failed: {error}"))?;
    if target_meta.file_type().is_symlink()||!target_meta.is_dir()||Some(target_meta.dev())!=current.target_device||Some(target_meta.ino())!=current.target_inode{return Err("mem0-maintenance-target-preimage-changed".into());}
    let predecessor=predecessor_path(request);
    let predecessor_exists=match fs::symlink_metadata(&predecessor){Ok(meta)=>{if meta.file_type().is_symlink()||!meta.is_dir(){return Err("mem0-maintenance-predecessor-collision-foreign-path".into());}validate_predecessor(&predecessor,owner,&request.subtree)?;true},Err(error)if error.kind()==std::io::ErrorKind::NotFound=>false,Err(error)=>return Err(format!("mem0-maintenance-predecessor-observe-failed: {error}"))};
    let previous_runtime=if let(Some(head),Some(tree))=(&current.recorded_head,&current.recorded_tree){let witness=ask::runtime_witness(request,head,tree,None)?;if !witness.ok{return Err(witness.first_missing_signal.unwrap_or_else(||"mem0-maintenance-runtime-preflight-unproven".into()));}witness}else{let witness=ask::runtime_witness(request,"","",None)?;let bound=witness.cwd_binding==Some(true)||witness.cmdline_binding==Some(true);if witness.main_pid.is_none()||witness.start_monotonic_usec.is_none()||!witness.health.starts_with("http_status=2")||!witness.health.contains("semantic_ok=true")||!bound||witness.first_missing_signal.as_deref().is_some_and(|signal|signal!="process-source-identity-does-not-match-promoted-tree"){return Err(witness.first_missing_signal.unwrap_or_else(||"mem0-maintenance-runtime-readback-preflight-unavailable".into()));}witness};
    if previous_runtime.main_pid.is_none()||previous_runtime.boot_id.is_none(){return Err("mem0-maintenance-runtime-freshness-preflight-unavailable".into());}
    let stage=create_stage(&app_root,owner)?;
    let staged=(||{let staged_subtree=stage.join(&request.subtree);ensure_stage_directories(&stage,&staged_subtree,owner)?;stream_tree_to(&current.source_tree,&source_root,&staged_subtree,owner)?;write_identity(&stage,owner,"SOURCE_HEAD",&current.source_head)?;write_identity(&stage,owner,"SOURCE_TREE",&current.source_tree)?;validate_managed_root(&stage,&request.subtree,owner,false,TreeMode::Canonical)?;File::open(&stage).and_then(|dir|dir.sync_all()).map_err(|error|format!("mem0-maintenance-staged-root-sync-failed: {error}"))?;Ok::<(),String>(())})();
    if let Err(error)=staged{return Err(with_stage_cleanup(error,&stage,owner));}
    let after=match ask::observe_unlocked(request){Ok(value)=>value,Err(error)=>return Err(with_stage_cleanup(error,&stage,owner))};
    if after.source_head!=current.source_head||after.source_tree!=current.source_tree||after.recorded_tree!=current.recorded_tree||after.target_device!=current.target_device||after.target_inode!=current.target_inode||after.app_root_device!=current.app_root_device||after.app_root_inode!=current.app_root_inode{return Err(with_stage_cleanup("mem0-maintenance-preimage-changed-during-stage".into(),&stage,owner));}
    if let Err(error)=rename_exchange(&app_root,&stage){return Err(with_stage_cleanup(format!("mem0-maintenance-atomic-app-root-exchange-failed: {error}"),&stage,owner));}
    // Capture the actual promotion boundary immediately after the single whole-root exchange.
    let boundary=match capture_promotion_boundary(){Ok(value)=>value,Err(error)=>{let rollback=rollback_root(&app_root,&stage);let restored=rollback.is_ok();let rollback_boundary=rollback.ok().flatten();let rr=restart_after_rollback(authorization,invocation,unit,request,&current,rollback_boundary.as_ref());let cleanup=if restored{remove_tree(&stage,owner,false)}else{Ok(())};let mut signal=format!("promotion-boundary-capture-failed-{error}");if !restored{signal.push_str("; rollback-refused-debt=atomic-whole-root-rollback-failed");}if let Err(debt)=rr{signal.push_str(&format!("; rollback-restart-or-readback-failed={debt}"));}if let Err(debt)=cleanup{signal.push_str(&format!("; stage-cleanup-refused-debt={debt}"));}return Ok(Movement::failed_after_restore(signal,"not-proven",None,!restored,rollback_boundary));}};
    let restart=unit_change_scoped(authorization,invocation,unit,UnitVerb::Restart,false,None,request.timeout_secs);let restart_ok=restart.as_ref().is_ok_and(|result|result.ok);
    let restart_label=match &restart{Ok(result)if result.ok=>format!("restart-exit-{:?}",result.code),Ok(result)=>format!("restart-failed-exit-{:?}",result.code),Err(_)=>"restart-command-failed".into()};
    let witness=match ask::runtime_witness(request,&current.source_head,&current.source_tree,Some(&boundary)){Ok(value)=>value,Err(error)=>ask::RuntimeWitness::missing(&error,"health-readback-failed")};
    if restart_ok&&witness.ok{
        let marker=format!("harmonia.mem0-maintenance.predecessor.v1\nowner_uid={}\nsource_head={}\nsource_tree={}\n",owner.0,current.recorded_head.as_deref().unwrap_or("unknown"),current.recorded_tree.as_deref().unwrap_or("unknown"));
        if let Err(error)=write_marker(&stage,owner,&marker){return rollback_after_failed_promotion(authorization,invocation,unit,request,&current,&stage,&app_root,owner,&boundary,&restart_label,Some(witness),format!("predecessor-marker-write-failed-{error}"));}
        if predecessor_exists{
            if let Err(error)=rename_exchange(&stage,&predecessor){let marker_result=remove_marker(&stage,owner);if let Err(debt)=marker_result{return Ok(Movement::promoted_with_debt(format!("predecessor-exchange-failed-{error}; marker-cleanup-refused-debt={debt}"),&restart_label,witness,&boundary));}return rollback_after_failed_promotion(authorization,invocation,unit,request,&current,&stage,&app_root,owner,&boundary,&restart_label,None,format!("predecessor-exchange-failed-{error}"));}
            if let Err(error)=remove_tree(&stage,owner,true){return Ok(Movement::promoted_with_debt(format!("predecessor-cleanup-refused-debt={error}"),&restart_label,witness,&boundary));}
        }else if let Err(error)=rename_noreplace(&stage,&predecessor){let marker_result=remove_marker(&stage,owner);if let Err(debt)=marker_result{return Ok(Movement::promoted_with_debt(format!("predecessor-noreplace-failed-{error}; marker-cleanup-refused-debt={debt}"),&restart_label,witness,&boundary));}return rollback_after_failed_promotion(authorization,invocation,unit,request,&current,&stage,&app_root,owner,&boundary,&restart_label,None,format!("predecessor-noreplace-failed-{error}"));}
        return Ok(Movement::proved(restart_label,witness,&boundary));
    }
    let why=if !restart_ok{"systemd-restart-failed".to_string()}else{witness.first_missing_signal.clone().unwrap_or_else(||"post-restart-runtime-unproven".into())};
    rollback_after_failed_promotion(authorization,invocation,unit,request,&current,&stage,&app_root,owner,&boundary,&restart_label,Some(witness),why)
}
fn rollback_after_failed_promotion(authorization:&ActionAuthorization,invocation:&InvocationKey,unit:&str,request:&Request,previous:&ask::Observation,stage:&Path,app_root:&Path,owner:(u32,u32),failed_boundary:&ask::PromotionBoundary,restart_label:&str,witness:Option<ask::RuntimeWitness>,reason:String)->Result<Movement,String>{
    let rollback=match rollback_root(app_root,stage){Ok(value)=>value,Err(error)=>return Ok(Movement::failed_after_restore(format!("{reason}; rollback-refused-debt={error}"),restart_label,witness,true,Some(failed_boundary.clone())))};
    let rr=restart_after_rollback(authorization,invocation,unit,request,previous,rollback.as_ref());let cleanup=remove_tree(stage,owner,false);let mut signal=reason;if let Err(error)=rr{signal.push_str(&format!("; rollback-restart-or-readback-failed={error}"));}if let Err(error)=cleanup{signal.push_str(&format!("; stage-cleanup-refused-debt={error}"));}Ok(Movement::failed_after_restore(signal,restart_label,witness,false,rollback))
}

fn restart_after_rollback(authorization:&ActionAuthorization,invocation:&InvocationKey,unit:&str,request:&Request,observed:&ask::Observation,boundary:Option<&ask::PromotionBoundary>)->Result<(),String>{let restart=unit_change_scoped(authorization,invocation,unit,UnitVerb::Restart,false,None,request.timeout_secs)?;if !restart.ok{return Err(format!("systemd-restart-exit-{:?}",restart.code));}let boundary=boundary.ok_or("rollback-promotion-boundary-unavailable")?;let(Some(head),Some(tree))=(observed.recorded_head.as_deref(),observed.recorded_tree.as_deref())else{return Err("rollback-runtime-identity-unavailable".into());};let witness=ask::runtime_witness(request,head,tree,Some(boundary))?;if !witness.ok{return Err(witness.first_missing_signal.unwrap_or_else(||"rollback-runtime-unproven".into()));}Ok(())}
fn read_owned_file(path:&Path,owner:(u32,u32))->Result<Option<Vec<u8>>,String>{let metadata=match fs::symlink_metadata(path){Ok(v)=>v,Err(e)if e.kind()==std::io::ErrorKind::NotFound=>return Ok(None),Err(e)=>return Err(e.to_string())};if metadata.file_type().is_symlink()||!metadata.is_file()||metadata.uid()!=owner.0||metadata.gid()!=owner.1||metadata.nlink()!=1||metadata.len()>512{return Err("mem0-maintenance-identity-file-custody-mismatch".into());}let mut file=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).open(path).map_err(|e|e.to_string())?;let mut bytes=Vec::new();file.take(513).read_to_end(&mut bytes).map_err(|e|e.to_string())?;Ok(Some(bytes))}
fn write_identity(root:&Path,owner:(u32,u32),name:&str,value:&str)->Result<(),String>{let path=root.join(name);let mut file=OpenOptions::new().write(true).create_new(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).mode(0o600).open(&path).map_err(|e|format!("mem0-maintenance-{name}-stage-create-failed: {e}"))?;set_owner_mode(&file,owner,0o644)?;file.write_all(format!("{value}\n").as_bytes()).map_err(|e|e.to_string())?;file.sync_all().map_err(|e|e.to_string())}

fn create_stage(app_root: &Path, owner: (u32,u32)) -> Result<PathBuf,String> {
    let parent = app_root.parent().ok_or("mem0-maintenance-app-root-parent-missing")?;
    let name = app_root.file_name().and_then(|name| name.to_str()).ok_or("mem0-maintenance-app-root-name-not-utf8")?;
    let stage = parent.join(format!(".{name}.mem0-maintenance-stage"));
    match fs::create_dir(&stage) {
        Ok(()) => {
            if let Err(error) = set_directory_owner_mode(&stage, owner, 0o700) {
                let _ = fs::remove_dir(&stage);
                return Err(error);
            }
            Ok(stage)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err("mem0-maintenance-stage-held-conflict".into())
        }
        Err(error) => Err(format!("mem0-maintenance-stage-create-failed: {error}")),
    }
}
fn set_directory_owner_mode(path: &Path, owner: (u32,u32), mode: u32) -> Result<(),String> {
    let dir = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path).map_err(|error| error.to_string())?;
    set_owner_mode(&dir, owner, mode)
}
fn validate_target_parent(root: &Path, subtree: &Path, owner: (u32,u32)) -> Result<(),String> {
    let mut current = root.to_path_buf();
    let mut parts = subtree.components().peekable();
    while let Some(std::path::Component::Normal(part)) = parts.next() {
        current.push(part);
        if parts.peek().is_some() {
            let metadata = fs::symlink_metadata(&current).map_err(|error| format!("mem0-maintenance-target-parent-unavailable: {error}"))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.uid() != owner.0 || metadata.gid() != owner.1 { return Err("mem0-maintenance-target-parent-custody-mismatch".into()); }
        }
    }
    Ok(())
}
fn validate_owned_tree(root: &Path, owner: (u32,u32), allow_marker: bool, mode: TreeMode) -> Result<(),String> {
    let root_device = fs::symlink_metadata(root).map_err(|error| error.to_string())?.dev();
    let mut count = 0u64; let mut bytes = 0u64;
    walk_owned(root, owner, allow_marker, mode, root_device, 0, &mut count, &mut bytes)
}
fn walk_owned(path: &Path, owner: (u32,u32), allow_marker: bool, mode: TreeMode, root_device: u64, depth: usize, count: &mut u64, bytes: &mut u64) -> Result<(),String> {
    if depth > 128 { return Err("mem0-maintenance-tree-depth-over-bound".into()); }
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || metadata.uid() != owner.0 || metadata.gid() != owner.1 { return Err("mem0-maintenance-tree-owner-or-link-custody-mismatch".into()); }
    if metadata.dev() != root_device { return Err("mem0-maintenance-tree-mount-crossing-refused".into()); }
    let permissions = metadata.permissions().mode();
    if permissions & 0o7000 != 0 { return Err("mem0-maintenance-tree-special-mode-refused".into()); }
    if metadata.is_dir() {
        if (depth == 0 || matches!(mode, TreeMode::Canonical)) && permissions & 0o777 != 0o700 { return Err("mem0-maintenance-tree-directory-mode-mismatch".into()); }
        for entry in fs::read_dir(path).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            *count += 1; if *count > 200_000 { return Err("mem0-maintenance-tree-entry-count-over-bound".into()); }
            if allow_marker && depth == 0 && entry.file_name() == PREDECESSOR_MARKER { continue; }
            walk_owned(&entry.path(), owner, allow_marker, mode, root_device, depth + 1, count, bytes)?;
        }
    } else if metadata.is_file() {
        if metadata.nlink() != 1 { return Err("mem0-maintenance-tree-hardlink-refused".into()); }
        if matches!(mode, TreeMode::Canonical) && permissions & 0o777 != 0o644 { return Err("mem0-maintenance-tree-file-mode-mismatch".into()); }
        *bytes = bytes.saturating_add(metadata.len()); if *bytes > 512 * 1024 * 1024 { return Err("mem0-maintenance-tree-size-over-bound".into()); }
    } else { return Err("mem0-maintenance-tree-contains-special-file".into()); }
    Ok(())
}
fn validate_predecessor(path:&Path,owner:(u32,u32),subtree:&Path)->Result<(),String>{
    let marker=path.join(PREDECESSOR_MARKER);let bytes=read_owned_file(&marker,owner)?.ok_or("mem0-maintenance-predecessor-marker-missing")?;
    let text=std::str::from_utf8(&bytes).map_err(|_|"mem0-maintenance-predecessor-marker-invalid")?;
    if !text.starts_with(&format!("harmonia.mem0-maintenance.predecessor.v1\nowner_uid={}\n",owner.0)){return Err("mem0-maintenance-predecessor-marker-custody-mismatch".into());}
    validate_managed_root(path,subtree,owner,true,TreeMode::Legacy)
}
fn validate_managed_root(root:&Path,subtree:&Path,owner:(u32,u32),allow_marker:bool,mode:TreeMode)->Result<(),String>{
    validate_owned_tree(root,owner,allow_marker,mode)?;
    let parts:Vec<_>=subtree.components().filter_map(|part|match part{std::path::Component::Normal(value)=>Some(value.to_os_string()),_=>None}).collect();
    if parts.is_empty(){return Err("mem0-maintenance-subtree-empty".into());}
    let mut allowed=vec![parts[0].clone(),"SOURCE_HEAD".into(),"SOURCE_TREE".into()];if allow_marker{allowed.push(PREDECESSOR_MARKER.into());}
    for entry in fs::read_dir(root).map_err(|error|error.to_string())?{let entry=entry.map_err(|error|error.to_string())?;if !allowed.iter().any(|name|name==&entry.file_name()){return Err("mem0-maintenance-app-root-contains-unexpected-entry".into());}}
    let managed=root.join(subtree);let meta=fs::symlink_metadata(&managed).map_err(|_|"mem0-maintenance-managed-subtree-absent")?;
    if meta.file_type().is_symlink()||!meta.is_dir(){return Err("mem0-maintenance-managed-subtree-not-plain-directory".into());}
    for index in 0..parts.len().saturating_sub(1){let mut parent=root.to_path_buf();for component in parts.iter().take(index+1){parent.push(component);}let expected=&parts[index+1];let mut entries=fs::read_dir(parent).map_err(|error|error.to_string())?;let Some(entry)=entries.next()else{return Err("mem0-maintenance-app-root-subtree-ancestor-empty".into());};let entry=entry.map_err(|error|error.to_string())?;if entry.file_name()!=*expected||entries.next().is_some(){return Err("mem0-maintenance-app-root-contains-unexpected-content".into());}}
    if !allow_marker&&fs::symlink_metadata(root.join(PREDECESSOR_MARKER)).is_ok(){return Err("mem0-maintenance-app-root-predecessor-marker-collision".into());}Ok(())
}

fn write_marker(path:&Path,owner:(u32,u32),contents:&str)->Result<(),String>{let marker=path.join(PREDECESSOR_MARKER);let mut file=OpenOptions::new().write(true).create_new(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).mode(0o600).open(&marker).map_err(|error|format!("mem0-maintenance-predecessor-marker-create-failed: {error}"))?;let result=(||{set_owner_mode(&file,owner,0o644)?;file.write_all(contents.as_bytes()).map_err(|error|error.to_string())?;file.sync_all().map_err(|error|error.to_string())})();if result.is_err(){drop(file);let _=fs::remove_file(marker);}result}

fn remove_tree(path: &Path, owner: (u32,u32), predecessor: bool) -> Result<(),String> {
    let mode = if predecessor { TreeMode::Legacy } else { TreeMode::Canonical };
    validate_owned_tree(path, owner, predecessor, mode)?;
    if predecessor { remove_marker(path, owner)?; }
    remove_tree_inner(path, owner, false)
}
fn with_stage_cleanup(signal: String, stage: &Path, owner: (u32,u32)) -> String {
    match remove_tree(stage, owner, false) {
        Ok(()) => signal,
        Err(error) => format!("{signal}; stage-cleanup-refused-debt={error}"),
    }
}
fn remove_tree_inner(path: &Path, owner: (u32,u32), predecessor: bool) -> Result<(),String> {
    for entry in fs::read_dir(path).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let child = entry.path();
        let metadata = fs::symlink_metadata(&child).map_err(|error| error.to_string())?;
        if predecessor && entry.file_name() == PREDECESSOR_MARKER {
            fs::remove_file(child).map_err(|error| error.to_string())?;
        } else if metadata.is_dir() && !metadata.file_type().is_symlink() {
            remove_tree_inner(&child, owner, predecessor)?;
        } else if metadata.is_file() && !metadata.file_type().is_symlink() && metadata.uid() == owner.0 && metadata.gid() == owner.1 && metadata.nlink() == 1 {
            fs::remove_file(child).map_err(|error| error.to_string())?;
        } else { return Err("mem0-maintenance-tree-delete-refused-foreign-path".into()); }
    }
    fs::remove_dir(path).map_err(|error| error.to_string())
}

fn remove_marker(path: &Path, owner: (u32,u32)) -> Result<(),String> {
    let marker = path.join(PREDECESSOR_MARKER);
    match read_owned_file(&marker, owner)? {
        Some(_) => fs::remove_file(marker).map_err(|error| error.to_string()),
        None => Ok(()),
    }
}
fn set_owner_mode(file:&File,owner:(u32,u32),mode:u32)->Result<(),String>{if unsafe{libc::fchown(file.as_raw_fd(),owner.0,owner.1)}!=0{return Err(format!("mem0-maintenance-owner-set-failed: {}",std::io::Error::last_os_error()));}if unsafe{libc::fchmod(file.as_raw_fd(),mode as libc::mode_t)}!=0{return Err(format!("mem0-maintenance-mode-set-failed: {}",std::io::Error::last_os_error()));}Ok(())}
fn valid_oid(value:&str)->bool{matches!(value.len(),40|64)&&value.bytes().all(|byte|byte.is_ascii_hexdigit()&&!byte.is_ascii_uppercase())}
fn stream_tree_to(tree:&str,source_root:&Path,destination:&Path,owner:(u32,u32))->Result<u64,String>{
 let mut cmd=std::process::Command::new("/usr/bin/git");cmd.arg("-C").arg(source_root).args(["ls-tree","-r","-z","--full-tree",tree]).env_clear().env("PATH","/usr/bin:/bin").env("GIT_NO_LAZY_FETCH","1").env("GIT_OPTIONAL_LOCKS","0").env("GIT_TERMINAL_PROMPT","0").stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null());
 let mut child=cmd.spawn().map_err(|e|format!("mem0-maintenance-git-list-spawn-failed: {e}"))?;let stdout=child.stdout.take().ok_or("git-tree-list-stdout-unavailable")?;let mut reader=BufReader::new(stdout);let mut listing=0u64;let mut copied=0u64;
 loop{let record=match read_nul_entry(&mut reader,TREE_LIST_ENTRY_LIMIT){Ok(value)=>value,Err(error)=>{let _=child.kill();let _=child.wait();return Err(error);}};let Some((entry,count))=record else{break;};listing=listing.saturating_add(count as u64);if listing>TREE_LIST_TOTAL_LIMIT{let _=child.kill();let _=child.wait();return Err("mem0-maintenance-git-tree-list-over-bound".into());}
 let tab=entry.iter().position(|b|*b==b'\t').ok_or("mem0-maintenance-git-tree-entry-malformed")?;let header=std::str::from_utf8(&entry[..tab]).map_err(|_|"mem0-maintenance-git-tree-header-not-utf8")?;let mut fields=header.split_whitespace();let mode=fields.next().unwrap_or("");let kind=fields.next().unwrap_or("");let oid=fields.next().unwrap_or("");if fields.next().is_some()||kind!="blob"||!matches!(mode,"100644"|"100755")||!valid_oid(oid){let _=child.kill();let _=child.wait();return Err("mem0-maintenance-source-tree-contains-symlink-gitlink-or-unsupported-object".into());}
 let relative=safe_git_relative_path(&entry[tab+1..])?;let size=git_blob_size(source_root,oid)?;if size>FILE_LIMIT||copied.saturating_add(size)>TREE_BYTES_LIMIT{let _=child.kill();let _=child.wait();return Err("mem0-maintenance-source-tree-over-copy-bound".into());}let full=destination.join(relative);let parent=full.parent().ok_or("mem0-maintenance-source-path-parent-missing")?;ensure_stage_directories(destination,parent,owner)?;
 let mut file=OpenOptions::new().write(true).create_new(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).mode(0o600).open(&full).map_err(|e|format!("mem0-maintenance-stage-file-create-failed: {e}"))?;set_owner_mode(&file,owner,0o644)?;stream_blob(source_root,oid,size,&mut file)?;file.sync_all().map_err(|e|format!("mem0-maintenance-stage-file-sync-failed: {e}"))?;copied=copied.saturating_add(size);}
 let status=child.wait().map_err(|e|format!("mem0-maintenance-git-list-wait-failed: {e}"))?;if !status.success(){return Err("mem0-maintenance-git-tree-list-failed".into());}Ok(copied)
}
fn read_nul_entry<R:BufRead>(reader:&mut R,limit:usize)->Result<Option<(Vec<u8>,usize)>,String>{let mut entry=Vec::new();loop{let available=reader.fill_buf().map_err(|e|format!("mem0-maintenance-git-tree-list-read-failed: {e}"))?;if available.is_empty(){return if entry.is_empty(){Ok(None)}else{Err("mem0-maintenance-git-tree-entry-unterminated".into())};}let end=available.iter().position(|b|*b==0);let take=end.map(|pos|pos+1).unwrap_or(available.len());if entry.len().saturating_add(take)>limit{return Err("mem0-maintenance-git-tree-entry-over-bound".into());}let terminated=end.is_some();let payload=if terminated{take-1}else{take};entry.extend_from_slice(&available[..payload]);reader.consume(take);if terminated{let count=entry.len()+1;return Ok(Some((entry,count)));}}}
fn safe_git_relative_path(bytes:&[u8])->Result<PathBuf,String>{if bytes.is_empty()||bytes.len()>4096||bytes[0]==b'/'||bytes.contains(&0){return Err("mem0-maintenance-source-path-unsafe".into());}if bytes.split(|b|*b==b'/').any(|part|part.is_empty()||part==b"."||part==b".."||part==PREDECESSOR_MARKER.as_bytes()){return Err("mem0-maintenance-source-path-unsafe-or-reserved".into());}Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec())))}
fn ensure_stage_directories(root:&Path,parent:&Path,owner:(u32,u32))->Result<(),String>{let relative=parent.strip_prefix(root).map_err(|_|"mem0-maintenance-stage-path-escape")?;let mut current=root.to_path_buf();for component in relative.components(){let std::path::Component::Normal(part)=component else{return Err("mem0-maintenance-stage-path-unsafe".into());};current.push(part);match fs::create_dir(&current){Ok(())=>{let dir=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).open(&current).map_err(|e|e.to_string())?;set_owner_mode(&dir,owner,0o700)?;}Err(e)if e.kind()==std::io::ErrorKind::AlreadyExists=>{let meta=fs::symlink_metadata(&current).map_err(|e|e.to_string())?;if meta.file_type().is_symlink()||!meta.is_dir()||meta.uid()!=owner.0||meta.gid()!=owner.1||meta.permissions().mode()&0o777!=0o700{return Err("mem0-maintenance-stage-directory-custody-mismatch".into());}}Err(e)=>return Err(format!("mem0-maintenance-stage-directory-create-failed: {e}")),}}Ok(())}
fn git_blob_size(root:&Path,oid:&str)->Result<u64,String>{ask::git_text(root,&["cat-file","-s",oid])?.parse::<u64>().map_err(|_|"mem0-maintenance-git-blob-size-invalid".into())}
fn stream_blob(root:&Path,oid:&str,expected:u64,destination:&mut File)->Result<(),String>{let mut child=std::process::Command::new("/usr/bin/git").arg("-C").arg(root).args(["cat-file","blob",oid]).env_clear().env("PATH","/usr/bin:/bin").env("GIT_NO_LAZY_FETCH","1").env("GIT_OPTIONAL_LOCKS","0").env("GIT_TERMINAL_PROMPT","0").stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).spawn().map_err(|e|e.to_string())?;let mut stdout=child.stdout.take().ok_or("git-blob-stdout-unavailable")?;let mut bounded=(&mut stdout).take(expected.saturating_add(1));let copied=std::io::copy(&mut bounded,destination).map_err(|e|format!("mem0-maintenance-blob-copy-failed: {e}"))?;if copied!=expected{let _=child.kill();let _=child.wait();return Err("mem0-maintenance-git-blob-length-mismatch".into());}let status=child.wait().map_err(|e|e.to_string())?;if !status.success(){return Err("mem0-maintenance-git-blob-read-failed".into());}Ok(())}

fn rename_noreplace(source: &Path, destination: &Path) -> Result<(),String> {
    let source = CString::new(source.as_os_str().as_bytes()).map_err(|_| "mem0-maintenance-rename-path-invalid")?;
    let destination = CString::new(destination.as_os_str().as_bytes()).map_err(|_| "mem0-maintenance-rename-path-invalid")?;
    let result = unsafe { libc::syscall(libc::SYS_renameat2, libc::AT_FDCWD, source.as_ptr(), libc::AT_FDCWD, destination.as_ptr(), libc::RENAME_NOREPLACE) };
    if result == 0 { Ok(()) } else { Err(format!("mem0-maintenance-predecessor-noreplace-failed: {}", std::io::Error::last_os_error())) }
}
fn rename_exchange(left: &Path, right: &Path) -> Result<(),String> {
    let left = CString::new(left.as_os_str().as_bytes()).map_err(|_| "mem0-maintenance-rename-path-invalid")?;
    let right = CString::new(right.as_os_str().as_bytes()).map_err(|_| "mem0-maintenance-rename-path-invalid")?;
    let result = unsafe { libc::syscall(libc::SYS_renameat2, libc::AT_FDCWD, left.as_ptr(), libc::AT_FDCWD, right.as_ptr(), libc::RENAME_EXCHANGE) };
    if result == 0 { Ok(()) } else { Err(std::io::Error::last_os_error().to_string()) }
}

fn capture_promotion_boundary()->Result<ask::PromotionBoundary,String>{let boot_id=fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|e|format!("promotion-boot-id-read-failed-{e}"))?.trim().to_owned();if boot_id.is_empty(){return Err("promotion-boot-id-empty".into());}let mut now=libc::timespec{tv_sec:0,tv_nsec:0};if unsafe{libc::clock_gettime(libc::CLOCK_MONOTONIC,&mut now)}!=0{return Err(format!("promotion-monotonic-clock-read-failed-{}",std::io::Error::last_os_error()));}let sec=u64::try_from(now.tv_sec).map_err(|_|"promotion-monotonic-seconds-invalid")?;let sub=u64::try_from(now.tv_nsec/1000).map_err(|_|"promotion-monotonic-nanoseconds-invalid")?;let usec=sec.checked_mul(1_000_000).and_then(|v|v.checked_add(sub)).ok_or("promotion-monotonic-usec-overflow")?;Ok(ask::PromotionBoundary{boot_id,monotonic_usec:usec})}
fn rollback_root(app_root:&Path,stage:&Path)->Result<Option<ask::PromotionBoundary>,String>{rename_exchange(app_root,stage).map_err(|e|format!("atomic-whole-root-rollback-failed-{e}"))?;Ok(capture_promotion_boundary().ok())}

impl Movement {
    fn current()->Self{Self{ok:true,changed:false,status:"current".into(),restart:None,health:None,runtime_identity:None,identity_evidence:None,process_main_pid:None,process_start_monotonic_usec:None,process_boot_id:None,process_cwd_binding:None,process_cmdline_binding:None,promotion_boot_id:None,promotion_monotonic_usec:None,first_missing_signal:None,duration_ms:0}}
    fn failure(signal:&str,duration_ms:u128)->Self{Self{ok:false,changed:false,status:"refused".into(),restart:None,health:None,runtime_identity:None,identity_evidence:None,process_main_pid:None,process_start_monotonic_usec:None,process_boot_id:None,process_cwd_binding:None,process_cmdline_binding:None,promotion_boot_id:None,promotion_monotonic_usec:None,first_missing_signal:Some(signal.to_owned()),duration_ms}}
    fn failed_after_restore(signal:String,restart:&str,witness:Option<ask::RuntimeWitness>,changed:bool,boundary:Option<ask::PromotionBoundary>)->Self{Self{ok:false,changed,status:if changed{"rollback-unproven-tree-may-stand".into()}else{"rolled-back-or-unproven".into()},restart:Some(restart.to_owned()),health:witness.as_ref().map(|v|v.health.clone()),runtime_identity:witness.as_ref().and_then(|v|v.runtime_identity.clone()),identity_evidence:witness.as_ref().and_then(|v|v.identity_evidence.clone()),process_main_pid:witness.as_ref().and_then(|v|v.main_pid),process_start_monotonic_usec:witness.as_ref().and_then(|v|v.start_monotonic_usec.clone()),process_boot_id:witness.as_ref().and_then(|v|v.boot_id.clone()),process_cwd_binding:witness.as_ref().and_then(|v|v.cwd_binding),process_cmdline_binding:witness.as_ref().and_then(|v|v.cmdline_binding),promotion_boot_id:boundary.as_ref().map(|v|v.boot_id.clone()),promotion_monotonic_usec:boundary.map(|v|v.monotonic_usec),first_missing_signal:Some(signal),duration_ms:0}}
    fn promoted_with_debt(signal:String,restart:&str,witness:ask::RuntimeWitness,boundary:&ask::PromotionBoundary)->Self{Self{ok:false,changed:true,status:"promoted-predecessor-retention-unproven".into(),restart:Some(restart.to_owned()),health:Some(witness.health),runtime_identity:witness.runtime_identity,identity_evidence:witness.identity_evidence,process_main_pid:witness.main_pid,process_start_monotonic_usec:witness.start_monotonic_usec,process_boot_id:witness.boot_id,process_cwd_binding:witness.cwd_binding,process_cmdline_binding:witness.cmdline_binding,promotion_boot_id:Some(boundary.boot_id.clone()),promotion_monotonic_usec:Some(boundary.monotonic_usec),first_missing_signal:Some(signal),duration_ms:0}}
    fn proved(restart:String,witness:ask::RuntimeWitness,boundary:&ask::PromotionBoundary)->Self{Self{ok:true,changed:true,status:"promoted-and-runtime-proven".into(),restart:Some(restart),health:Some(witness.health),runtime_identity:witness.runtime_identity,identity_evidence:witness.identity_evidence,process_main_pid:witness.main_pid,process_start_monotonic_usec:witness.start_monotonic_usec,process_boot_id:witness.boot_id,process_cwd_binding:witness.cwd_binding,process_cmdline_binding:witness.cmdline_binding,promotion_boot_id:Some(boundary.boot_id.clone()),promotion_monotonic_usec:Some(boundary.monotonic_usec),first_missing_signal:None,duration_ms:0}}
}
