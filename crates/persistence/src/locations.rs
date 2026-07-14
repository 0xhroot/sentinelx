pub const SYSTEMD_SYSTEM_DIRS: &[&str] = &[
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/run/systemd/system",
    "/lib/systemd/system",
];

pub const CRON_DIRS: &[&str] = &["/etc/cron.d", "/var/spool/cron/crontabs"];

pub const PROFILE_FILES: &[&str] = &[
    "~/.bashrc",
    "~/.profile",
    "/etc/profile",
    "/etc/bashrc",
    "/etc/bash.bashrc",
];

pub const PRELOAD_PATH: &str = "/etc/ld.so.preload";

pub const RC_LOCAL_PATHS: &[&str] = &["/etc/rc.local", "/etc/rc.d/rc.local"];
