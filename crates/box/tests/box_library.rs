//! Process protections and repeat-run refusal through the public library entry point.

#[cfg(unix)]
fn main() {
    if std::env::args().any(|argument| argument == "--probe") {
        hardening_and_repeat_run();
        return;
    }

    let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .arg("--probe")
        .output()
        .expect("run the library probe");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(stderr.contains("missing.toml"), "{stderr}");
    assert!(
        stderr.lines().any(|line| {
            line == "strands-box: refusing to run: this process already attempted to run a box"
        }),
        "{stderr}"
    );
}

#[cfg(unix)]
fn hardening_and_repeat_run() {
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes to the initialized limits value.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limits) },
        0
    );
    if limits.rlim_max > 0 {
        limits.rlim_cur = 1;
        // SAFETY: the new soft limit does not exceed the existing hard limit.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limits) }, 0);
    } else {
        eprintln!("core dumps already disabled; checking the final state only");
    }

    #[cfg(target_os = "linux")]
    {
        // SAFETY: this test process holds no Box credentials or workload.
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) }, 0);
        // SAFETY: PR_GET_DUMPABLE reads the current process setting.
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 1);
    }

    let directory = tempfile::tempdir().expect("create test directory");
    let config = directory.path().join("missing.toml");
    let exit_code = strands_box::run(config.clone(), Vec::new());
    assert_eq!(exit_code, std::process::ExitCode::FAILURE);

    // SAFETY: getrlimit writes to the initialized limits value.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limits) },
        0
    );
    assert_eq!(limits.rlim_cur, 0);
    assert_eq!(limits.rlim_max, 0);
    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_GET_DUMPABLE reads the current process setting.
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
    }

    assert_eq!(
        strands_box::run(config, Vec::new()),
        std::process::ExitCode::FAILURE
    );
}

#[cfg(not(unix))]
fn main() {
    eprintln!("skipping: process-protection test requires Unix");
}
