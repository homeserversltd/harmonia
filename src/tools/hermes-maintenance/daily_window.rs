//! Optional local-time admission and durable once-per-local-day proof for
//! Hermes maintenance. The date is read through GNU `date` with an explicit
//! `TZ=:/etc/localtime`; the inherited TZ environment never selects the zone.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const LOCALTIME_PATH: &str = "/etc/localtime";
const PASSWD_PATH: &str = "/etc/passwd";
const PASSWD_MAX_BYTES: u64 = 1024 * 1024;
const RECORD_BASE: &str = "/var/lib/harmonia";
const RECORD_DIRECTORY: &str = "hermes-maintenance-days";
const RECORD_MAX_BYTES: u64 = 4096;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy)]
pub(crate) struct Window {
    start_minute: u16,
    end_minute: u16,
}

#[derive(Debug, Clone)]
pub(crate) struct LocalClock {
    pub(crate) date: String,
    pub(crate) time: String,
    minute: u16,
}

#[derive(Debug)]
pub(crate) struct Permit {
    window: Window,
    press_start_clock: LocalClock,
    source_root_sha256: String,
    record_path: String,
    directories: SafeDirectories,
}

#[derive(Debug)]
struct SafeDirectories {
    base: File,
    days: Option<File>,
}

#[derive(Debug)]
enum RecordRead {
    Missing,
    Open,
    Valid { date: String, post_sha: String },
}

pub(crate) fn parse_args(args: &BTreeMap<String, Value>) -> Result<Option<Window>, String> {
    match args.get("daily_window") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => parse_window(value).map(Some),
        Some(_) => Err("hermes-maintenance-daily-window-malformed".into()),
    }
}

pub(crate) fn validate_args(args: &BTreeMap<String, Value>) -> Result<(), String> {
    parse_args(args).map(|_| ())
}

fn parse_window(value: &str) -> Result<Window, String> {
    let bytes = value.as_bytes();
    if bytes.len() != 11
        || bytes[2] != b':'
        || bytes[5] != b'-'
        || bytes[8] != b':'
        || [0, 1, 3, 4, 6, 7, 9, 10]
            .into_iter()
            .any(|index| !bytes[index].is_ascii_digit())
    {
        return Err("hermes-maintenance-daily-window-malformed".into());
    }
    let start_hour = two_digits(&bytes[0..2]);
    let start_minute = two_digits(&bytes[3..5]);
    let end_hour = two_digits(&bytes[6..8]);
    let end_minute = two_digits(&bytes[9..11]);
    if start_hour > 23 || end_hour > 23 || start_minute > 59 || end_minute > 59 {
        return Err("hermes-maintenance-daily-window-time-invalid".into());
    }
    let start_minute = start_hour * 60 + start_minute;
    let end_minute = end_hour * 60 + end_minute;
    if end_minute <= start_minute {
        return Err("hermes-maintenance-daily-window-reversed".into());
    }
    Ok(Window {
        start_minute,
        end_minute,
    })
}

fn two_digits(bytes: &[u8]) -> u16 {
    u16::from(bytes[0] - b'0') * 10 + u16::from(bytes[1] - b'0')
}

pub(crate) fn local_clock() -> Result<LocalClock, String> {
    let zone = std::fs::metadata(LOCALTIME_PATH).map_err(|error| {
        format!("hermes-maintenance-daily-window-timezone-unavailable: {error}")
    })?;
    if !zone.is_file() {
        return Err("hermes-maintenance-daily-window-timezone-invalid".into());
    }
    let mut zone_file = File::open(LOCALTIME_PATH).map_err(|error| {
        format!("hermes-maintenance-daily-window-timezone-unavailable: {error}")
    })?;
    let mut zone_header = [0_u8; 44];
    match zone_file.read_exact(&mut zone_header) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err("hermes-maintenance-daily-window-timezone-invalid".into());
        }
        Err(error) => {
            return Err(format!(
                "hermes-maintenance-daily-window-timezone-unavailable: {error}"
            ));
        }
    }
    if &zone_header[..4] != b"TZif" {
        return Err("hermes-maintenance-daily-window-timezone-invalid".into());
    }
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "hermes-maintenance-daily-window-clock-before-epoch")?
        .as_secs();
    if seconds > i64::MAX as u64 {
        return Err("hermes-maintenance-daily-window-clock-out-of-range".into());
    }
    let instant = format!("@{seconds}");
    let output = Command::new("/usr/bin/date")
        .env_clear()
        .env("TZ", ":/etc/localtime")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .arg("--date")
        .arg(instant)
        .arg("+%F %T")
        .output()
        .map_err(|error| format!("hermes-maintenance-daily-window-clock-unavailable: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "hermes-maintenance-daily-window-clock-unavailable: exit_code={:?}",
            output.status.code()
        ));
    }
    let rendered = std::str::from_utf8(&output.stdout)
        .map_err(|_| "hermes-maintenance-daily-window-clock-invalid")?
        .trim_end_matches('\n');
    if rendered.len() != 19 || rendered.as_bytes()[10] != b' ' {
        return Err("hermes-maintenance-daily-window-clock-invalid".into());
    }
    let date = &rendered[..10];
    let time = &rendered[11..];
    validate_date(date).map_err(|_| "hermes-maintenance-daily-window-clock-invalid")?;
    let time_bytes = time.as_bytes();
    if time_bytes.len() != 8
        || time_bytes[2] != b':'
        || time_bytes[5] != b':'
        || [0, 1, 3, 4, 6, 7]
            .into_iter()
            .any(|index| !time_bytes[index].is_ascii_digit())
    {
        return Err("hermes-maintenance-daily-window-clock-invalid".into());
    }
    let hour = two_digits(&time_bytes[0..2]);
    let minute = two_digits(&time_bytes[3..5]);
    let second = two_digits(&time_bytes[6..8]);
    if hour > 23 || minute > 59 || second > 60 {
        return Err("hermes-maintenance-daily-window-clock-invalid".into());
    }
    Ok(LocalClock {
        date: date.to_owned(),
        time: time.to_owned(),
        minute: hour * 60 + minute,
    })
}

pub(crate) fn outside(window: Window, clock: &LocalClock) -> bool {
    clock.minute < window.start_minute || clock.minute >= window.end_minute
}

pub(crate) fn outside_outputs(
    window: Window,
    clock: &LocalClock,
    configured: &str,
) -> Result<BTreeMap<String, Value>, String> {
    let next_date = if clock.minute < window.start_minute {
        clock.date.clone()
    } else {
        next_date(&clock.date)?
    };
    Ok(BTreeMap::from([
        ("reason".into(), Value::String("outside-window".into())),
        ("daily_window".into(), Value::String(configured.into())),
        ("local_date".into(), Value::String(clock.date.clone())),
        ("local_time".into(), Value::String(clock.time.clone())),
        ("zone_source".into(), Value::String(LOCALTIME_PATH.into())),
        (
            "next_window_start".into(),
            Value::String(window_start(&next_date, window)),
        ),
    ]))
}

pub(crate) fn open_permit(
    window: Window,
    clock: LocalClock,
    canonical_source_root: &Path,
    owner_name: &str,
) -> Result<(Permit, Option<BTreeMap<String, Value>>), String> {
    let install_owner_uid = resolve_local_owner_uid(owner_name)?;
    let directories = SafeDirectories::open(install_owner_uid)?;
    let source_root_sha256 = digest(canonical_source_root.as_os_str().as_bytes());
    let record_name = format!("{source_root_sha256}.json");
    let record_path = format!("{RECORD_BASE}/{RECORD_DIRECTORY}/{record_name}");
    let record = directories.read_record(&record_name, &source_root_sha256);
    if let RecordRead::Valid { date, post_sha } = record {
        if date == clock.date {
            let next_date = next_date(&clock.date)?;
            let outputs = BTreeMap::from([
                ("reason".into(), Value::String("moved-today".into())),
                ("daily_window".into(), Value::String(format_window(window))),
                ("local_date".into(), Value::String(clock.date.clone())),
                ("local_time".into(), Value::String(clock.time.clone())),
                ("zone_source".into(), Value::String(LOCALTIME_PATH.into())),
                (
                    "next_window_start".into(),
                    Value::String(window_start(&next_date, window)),
                ),
                ("post_sha".into(), Value::String(post_sha)),
                ("record_path".into(), Value::String(record_path.clone())),
            ]);
            return Ok((
                Permit {
                    window,
                    press_start_clock: clock,
                    source_root_sha256,
                    record_path,
                    directories,
                },
                Some(outputs),
            ));
        }
    }
    Ok((
        Permit {
            window,
            press_start_clock: clock,
            source_root_sha256,
            record_path,
            directories,
        },
        None,
    ))
}

impl Permit {
    pub(crate) fn record_path(&self) -> &str {
        &self.record_path
    }

    pub(crate) fn validate_install_owner_uid(&self, install_owner_uid: u32) -> Result<(), String> {
        validate_base_directory(&self.directories.base, install_owner_uid)
    }

    pub(crate) fn record_proven_move(
        &mut self,
        post_sha: &str,
    ) -> Result<BTreeMap<String, Value>, String> {
        if !valid_sha(post_sha) {
            return Err("hermes-maintenance-daily-window-post-sha-invalid".into());
        }
        let record = json!({
            "date": self.press_start_clock.date.clone(),
            "post_sha": post_sha,
            "source_root_sha256": self.source_root_sha256.clone(),
        });
        let bytes = serde_json::to_vec(&record).map_err(|error| {
            format!("hermes-maintenance-daily-window-record-serialize-failed: {error}")
        })?;
        self.directories.write_record(&self.record_path, &bytes)?;
        Ok(BTreeMap::from([
            (
                "reason".into(),
                Value::String("proven-move-recorded".into()),
            ),
            (
                "daily_window".into(),
                Value::String(format_window(self.window)),
            ),
            (
                "local_date".into(),
                Value::String(self.press_start_clock.date.clone()),
            ),
            (
                "local_time".into(),
                Value::String(self.press_start_clock.time.clone()),
            ),
            ("zone_source".into(), Value::String(LOCALTIME_PATH.into())),
            ("post_sha".into(), Value::String(post_sha.into())),
            (
                "record_path".into(),
                Value::String(self.record_path.clone()),
            ),
        ]))
    }
}

impl SafeDirectories {
    fn open(install_owner_uid: u32) -> Result<Self, String> {
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")
            .map_err(|error| {
                format!("hermes-maintenance-daily-window-record-base-unavailable: {error}")
            })?;
        let var = openat_directory(root.as_raw_fd(), "var").map_err(|error| {
            format!("hermes-maintenance-daily-window-record-base-unavailable: {error}")
        })?;
        let lib = openat_directory(var.as_raw_fd(), "lib").map_err(|error| {
            format!("hermes-maintenance-daily-window-record-base-unavailable: {error}")
        })?;
        let base = openat_directory(lib.as_raw_fd(), "harmonia").map_err(|error| {
            format!("hermes-maintenance-daily-window-record-base-unavailable: {error}")
        })?;
        validate_base_directory(&base, install_owner_uid)?;
        let days = match openat_directory(base.as_raw_fd(), RECORD_DIRECTORY) {
            Ok(directory) => {
                validate_days_directory(&directory)?;
                Some(directory)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(format!(
                    "hermes-maintenance-daily-window-record-directory-unsafe: {error}"
                ));
            }
        };
        Ok(Self { base, days })
    }

    fn read_record(&self, name: &str, expected_root_sha: &str) -> RecordRead {
        let Some(days) = self.days.as_ref() else {
            return RecordRead::Missing;
        };
        let name_c = match CString::new(name) {
            Ok(name) => name,
            Err(_) => return RecordRead::Open,
        };
        let mut observed = std::mem::MaybeUninit::<libc::stat>::uninit();
        let stat_result = unsafe {
            libc::fstatat(
                days.as_raw_fd(),
                name_c.as_ptr(),
                observed.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if stat_result != 0 {
            return if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
                RecordRead::Missing
            } else {
                RecordRead::Open
            };
        }
        let observed = unsafe { observed.assume_init() };
        let expected_uid = unsafe { libc::geteuid() };
        if observed.st_mode & libc::S_IFMT != libc::S_IFREG
            || observed.st_uid != expected_uid
            || observed.st_nlink != 1
            || observed.st_mode & 0o077 != 0
            || observed.st_mode & 0o400 == 0
            || observed.st_size < 0
            || observed.st_size as u64 > RECORD_MAX_BYTES
        {
            return RecordRead::Open;
        }
        let fd = unsafe {
            libc::openat(
                days.as_raw_fd(),
                name_c.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return RecordRead::Open;
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let metadata = match file.metadata() {
            Ok(metadata) => metadata,
            Err(_) => return RecordRead::Open,
        };
        if !metadata.is_file()
            || metadata.dev() != observed.st_dev
            || metadata.ino() != observed.st_ino
            || metadata.uid() != expected_uid
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
            || metadata.mode() & 0o400 == 0
            || metadata.len() > RECORD_MAX_BYTES
        {
            return RecordRead::Open;
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        if file.read_to_end(&mut bytes).is_err() || bytes.len() as u64 != metadata.len() {
            return RecordRead::Open;
        }
        let value: Value = match serde_json::from_slice(&bytes) {
            Ok(value) => value,
            Err(_) => return RecordRead::Open,
        };
        let Some(object) = value.as_object() else {
            return RecordRead::Open;
        };
        let Some(date) = object.get("date").and_then(Value::as_str) else {
            return RecordRead::Open;
        };
        let Some(post_sha) = object.get("post_sha").and_then(Value::as_str) else {
            return RecordRead::Open;
        };
        let Some(root_sha) = object.get("source_root_sha256").and_then(Value::as_str) else {
            return RecordRead::Open;
        };
        if validate_date(date).is_err() || !valid_sha(post_sha) || root_sha != expected_root_sha {
            return RecordRead::Open;
        }
        RecordRead::Valid {
            date: date.to_owned(),
            post_sha: post_sha.to_owned(),
        }
    }

    fn write_record(&mut self, record_path: &str, bytes: &[u8]) -> Result<(), String> {
        if self.days.is_none() {
            let name = CString::new(RECORD_DIRECTORY).expect("constant directory name");
            let result = unsafe { libc::mkdirat(self.base.as_raw_fd(), name.as_ptr(), 0o700) };
            let created = result == 0;
            if !created {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(format!(
                        "hermes-maintenance-daily-window-record-directory-create-failed: {error}"
                    ));
                }
            }
            let directory =
                openat_directory(self.base.as_raw_fd(), RECORD_DIRECTORY).map_err(|error| {
                    format!("hermes-maintenance-daily-window-record-directory-unsafe: {error}")
                })?;
            if created {
                validate_days_directory_owner(&directory)?;
                if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
                    return Err(format!(
                        "hermes-maintenance-daily-window-record-directory-mode-failed: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            }
            validate_days_directory(&directory)?;
            if created && unsafe { libc::fsync(self.base.as_raw_fd()) } != 0 {
                return Err(format!(
                    "hermes-maintenance-daily-window-record-base-sync-failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            self.days = Some(directory);
        }
        let days = self.days.as_ref().expect("record directory was opened");
        let file_name = Path::new(record_path)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("hermes-maintenance-daily-window-record-name-invalid")?;
        let mut temp_name = String::new();
        let mut temp_file = None;
        for _ in 0..32 {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            temp_name = format!(
                ".hermes-maintenance-day-{}-{sequence}.tmp",
                std::process::id()
            );
            let temp_c = CString::new(temp_name.as_str()).expect("generated temp name");
            let fd = unsafe {
                libc::openat(
                    days.as_raw_fd(),
                    temp_c.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd >= 0 {
                temp_file = Some(unsafe { File::from_raw_fd(fd) });
                break;
            }
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists {
                return Err(format!(
                    "hermes-maintenance-daily-window-record-temp-create-failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        let mut file = temp_file.ok_or("hermes-maintenance-daily-window-record-temp-collision")?;
        let write_result = (|| -> Result<(), String> {
            file.write_all(bytes).map_err(|error| {
                format!("hermes-maintenance-daily-window-record-write-failed: {error}")
            })?;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|error| {
                    format!("hermes-maintenance-daily-window-record-mode-failed: {error}")
                })?;
            file.sync_all().map_err(|error| {
                format!("hermes-maintenance-daily-window-record-sync-failed: {error}")
            })?;
            let metadata = file.metadata().map_err(|error| {
                format!("hermes-maintenance-daily-window-record-stat-failed: {error}")
            })?;
            if metadata.uid() != unsafe { libc::geteuid() }
                || metadata.nlink() != 1
                || metadata.mode() & 0o777 != 0o600
            {
                return Err("hermes-maintenance-daily-window-record-temp-custody-invalid".into());
            }
            Ok(())
        })();
        if let Err(error) = write_result {
            drop(file);
            unlinkat(days.as_raw_fd(), &temp_name);
            return Err(error);
        }
        drop(file);
        let temp_c = CString::new(temp_name.as_str()).expect("generated temp name");
        let final_c = CString::new(file_name)
            .map_err(|_| "hermes-maintenance-daily-window-record-name-invalid")?;
        let renamed = unsafe {
            libc::renameat(
                days.as_raw_fd(),
                temp_c.as_ptr(),
                days.as_raw_fd(),
                final_c.as_ptr(),
            )
        };
        if renamed != 0 {
            let error = std::io::Error::last_os_error();
            unlinkat(days.as_raw_fd(), &temp_name);
            return Err(format!(
                "hermes-maintenance-daily-window-record-promote-failed: {error}"
            ));
        }
        if unsafe { libc::fsync(days.as_raw_fd()) } != 0 {
            return Err(format!(
                "hermes-maintenance-daily-window-record-directory-sync-failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
}

fn openat_directory(parent_fd: i32, name: &str) -> std::io::Result<File> {
    let name = CString::new(name).expect("constant directory name");
    let fd = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn validate_base_directory(directory: &File, install_owner_uid: u32) -> Result<(), String> {
    let metadata = directory.metadata().map_err(|error| {
        format!("hermes-maintenance-daily-window-record-base-stat-failed: {error}")
    })?;
    if !metadata.is_dir()
        || !(metadata.uid() == unsafe { libc::geteuid() }
            || metadata.uid() == 0
            || metadata.uid() == install_owner_uid)
        || metadata.mode() & 0o022 != 0
    {
        return Err("hermes-maintenance-daily-window-record-base-unsafe".into());
    }
    Ok(())
}

fn validate_days_directory_owner(directory: &File) -> Result<(), String> {
    let metadata = directory.metadata().map_err(|error| {
        format!("hermes-maintenance-daily-window-record-days-stat-failed: {error}")
    })?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err("hermes-maintenance-daily-window-record-days-unsafe".into());
    }
    Ok(())
}

fn validate_days_directory(directory: &File) -> Result<(), String> {
    let metadata = directory.metadata().map_err(|error| {
        format!("hermes-maintenance-daily-window-record-days-stat-failed: {error}")
    })?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err("hermes-maintenance-daily-window-record-days-unsafe".into());
    }
    Ok(())
}

fn resolve_local_owner_uid(name: &str) -> Result<u32, String> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err("hermes-maintenance-daily-window-owner-name-invalid".into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(PASSWD_PATH)
        .map_err(|error| {
            format!("hermes-maintenance-daily-window-owner-passwd-unavailable: {error}")
        })?;
    let before = file.metadata().map_err(|error| {
        format!("hermes-maintenance-daily-window-owner-passwd-stat-failed: {error}")
    })?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
        || before.len() > PASSWD_MAX_BYTES
    {
        return Err("hermes-maintenance-daily-window-owner-passwd-unsafe".into());
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(PASSWD_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            format!("hermes-maintenance-daily-window-owner-passwd-read-failed: {error}")
        })?;
    let after = file.metadata().map_err(|error| {
        format!("hermes-maintenance-daily-window-owner-passwd-stat-failed: {error}")
    })?;
    if bytes.len() as u64 > PASSWD_MAX_BYTES
        || bytes.len() as u64 != before.len()
        || after.dev() != before.dev()
        || after.ino() != before.ino()
        || after.uid() != before.uid()
        || after.nlink() != before.nlink()
        || after.mode() != before.mode()
        || after.len() != before.len()
        || after.mtime() != before.mtime()
        || after.mtime_nsec() != before.mtime_nsec()
        || after.ctime() != before.ctime()
        || after.ctime_nsec() != before.ctime_nsec()
    {
        return Err("hermes-maintenance-daily-window-owner-passwd-changed-during-read".into());
    }
    let contents = std::str::from_utf8(&bytes)
        .map_err(|_| "hermes-maintenance-daily-window-owner-passwd-invalid")?;
    let mut resolved_uid = None;
    for line in contents.lines() {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.first().copied() != Some(name) {
            continue;
        }
        if fields.len() != 7
            || fields[2].is_empty()
            || !fields[2].bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err("hermes-maintenance-daily-window-owner-passwd-entry-invalid".into());
        }
        let uid = fields[2]
            .parse::<u32>()
            .map_err(|_| "hermes-maintenance-daily-window-owner-passwd-entry-invalid")?;
        if resolved_uid.replace(uid).is_some() {
            return Err("hermes-maintenance-daily-window-owner-passwd-entry-duplicate".into());
        }
    }
    resolved_uid.ok_or_else(|| {
        format!("hermes-maintenance-daily-window-owner-account-unknown-{name}")
    })
}

fn unlinkat(parent_fd: i32, name: &str) {
    if let Ok(name) = CString::new(name) {
        unsafe {
            libc::unlinkat(parent_fd, name.as_ptr(), 0);
        }
    }
}

fn digest(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn valid_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_date(date: &str) -> Result<(), ()> {
    let bytes = date.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || [0, 1, 2, 3, 5, 6, 8, 9]
            .into_iter()
            .any(|index| !bytes[index].is_ascii_digit())
    {
        return Err(());
    }
    let year = four_digits(&bytes[0..4]);
    let month = two_digits(&bytes[5..7]);
    let day = two_digits(&bytes[8..10]);
    let days = days_in_month(year, month).ok_or(())?;
    if year == 0 || day == 0 || day > days {
        return Err(());
    }
    Ok(())
}

fn four_digits(bytes: &[u8]) -> u16 {
    bytes
        .iter()
        .fold(0, |value, digit| value * 10 + u16::from(*digit - b'0'))
}

fn days_in_month(year: u16, month: u16) -> Option<u16> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 if year % 400 == 0 || (year % 4 == 0 && year % 100 != 0) => Some(29),
        2 => Some(28),
        _ => None,
    }
}

fn next_date(date: &str) -> Result<String, String> {
    validate_date(date).map_err(|_| "hermes-maintenance-daily-window-calendar-invalid")?;
    let bytes = date.as_bytes();
    let mut year = four_digits(&bytes[0..4]);
    let mut month = two_digits(&bytes[5..7]);
    let mut day = two_digits(&bytes[8..10]);
    day += 1;
    if day > days_in_month(year, month).expect("validated month") {
        day = 1;
        month += 1;
        if month > 12 {
            month = 1;
            year = year
                .checked_add(1)
                .filter(|year| *year <= 9999)
                .ok_or("hermes-maintenance-daily-window-calendar-overflow")?;
        }
    }
    Ok(format!("{year:04}-{month:02}-{day:02}"))
}

fn window_start(date: &str, window: Window) -> String {
    let hour = window.start_minute / 60;
    let minute = window.start_minute % 60;
    format!("{date}T{hour:02}:{minute:02}:00")
}

fn format_window(window: Window) -> String {
    format!(
        "{:02}:{:02}-{:02}:{:02}",
        window.start_minute / 60,
        window.start_minute % 60,
        window.end_minute / 60,
        window.end_minute % 60
    )
}
