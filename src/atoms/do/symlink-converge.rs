//! Authorized filesystem mutation owners for symlink convergence.
use crate::atoms::{Drift, Receipt};
use crate::atoms::r#do::{apply, InvocationKey};
use crate::tools::comparison::ActionAuthorization;
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
fn receipt(a: ActionAuthorization, i: InvocationKey, message: String) -> Result<(), String> { apply(a, i, Receipt { atom: "do".into(), ok: true, drift: Drift::Current, message }).map(|_| ()) }
pub(crate) fn stage(a: ActionAuthorization, i: InvocationKey, source: &Path, target: &Path, uid: Option<u32>, gid: Option<u32>) -> Result<PathBuf, String> {
 let parent=target.parent().ok_or_else(|| "symlink-converge-target-parent-missing".to_string())?; let name=target.file_name().and_then(|v|v.to_str()).unwrap_or("link");
 for attempt in 0..100u32 { let candidate=parent.join(format!(".{name}.harmonia-symlink-converge-{}-{attempt}",std::process::id())); match std::os::unix::fs::symlink(source,&candidate) { Ok(())=>{ if uid.is_some() || gid.is_some() { if let Err(error) = crate::atoms::r#do::change_owner::change(a, i, &crate::atoms::r#do::change_owner::Plan { path: candidate.clone(), uid, gid, no_follow: true }) { let _ = remove_file(a, i, &candidate); return Err(error); } } receipt(a,i,format!("staged symlink {}",candidate.display()))?;return Ok(candidate)}, Err(e) if e.kind()==std::io::ErrorKind::AlreadyExists=>continue, Err(e)=>return Err(format!("symlink-converge-stage-failed {}: {e}",candidate.display())) } }
 Err("symlink-converge-stage-name-exhausted".into())
}
fn renameat2(a:ActionAuthorization,i:InvocationKey,left:&Path,right:&Path,flags:libc::c_uint,message:&str)->Result<(),String>{ let l=CString::new(left.as_os_str().as_bytes()).map_err(|_|"symlink-converge-rename-path-invalid".to_string())?; let r=CString::new(right.as_os_str().as_bytes()).map_err(|_|"symlink-converge-rename-path-invalid".to_string())?; #[cfg(target_os="linux")] let rc=unsafe{libc::renameat2(libc::AT_FDCWD,l.as_ptr(),libc::AT_FDCWD,r.as_ptr(),flags)}; #[cfg(not(target_os="linux"))] let rc=-1; if rc!=0{return Err(std::io::Error::last_os_error().to_string())} receipt(a,i,format!("{message} {} {}",left.display(),right.display())) }
pub(crate) fn exchange(a:ActionAuthorization,i:InvocationKey,left:&Path,right:&Path)->Result<(),String>{renameat2(a,i,left,right,libc::RENAME_EXCHANGE,"exchanged")}
pub(crate) fn rename_noreplace(a:ActionAuthorization,i:InvocationKey,left:&Path,right:&Path)->Result<(),String>{renameat2(a,i,left,right,libc::RENAME_NOREPLACE,"promoted")}
pub(crate) fn remove_file(a:ActionAuthorization,i:InvocationKey,path:&Path)->Result<(),String>{fs::remove_file(path).map_err(|e|e.to_string())?;receipt(a,i,format!("removed file {}",path.display()))}
pub(crate) fn remove_dir(a:ActionAuthorization,i:InvocationKey,path:&Path)->Result<(),String>{fs::remove_dir(path).map_err(|e|e.to_string())?;receipt(a,i,format!("removed directory {}",path.display()))}
pub(crate) fn sync_parent(a:ActionAuthorization,i:InvocationKey,path:&Path)->Result<(),String>{let file=fs::File::open(path).map_err(|e|e.to_string())?;file.sync_all().map_err(|e|e.to_string())?;receipt(a,i,format!("synced directory {}",path.display()))}
