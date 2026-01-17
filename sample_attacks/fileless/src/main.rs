use std::{ffi::CString, fs::File, io::Write, os::unix::io::FromRawFd};

fn main() {
    unsafe {
        println!("😈 [MALWARE] Starting fileless execution simulation...");

        // STEP 1: Create the anonymous file (memfd)
        // This triggers sys_enter_memfd_create
        let name = CString::new("suspicious_payload").unwrap();
        let fd = libc::memfd_create(name.as_ptr(), 0);

        if fd < 0 {
            panic!("Failed to create memfd!");
        }
        println!("😈 [MALWARE] Created anonymous memfd: FD {}", fd);

        // STEP 2: Write a payload to it
        // We act like a downloader writing a binary.
        // Here we write a simple script that prints a message.
        let mut file = File::from_raw_fd(fd);
        let payload = b"#!/bin/sh\necho '!!! I AM RUNNING FROM MEMORY !!!'\n";
        file.write_all(payload).unwrap();

        // We must drop the file struct to avoid closing the FD,
        // but we need the FD open for exec.
        // 'from_raw_fd' takes ownership, so we forget it to keep FD open.
        std::mem::forget(file);

        println!("😈 [MALWARE] Payload written. Attempting execveat...");

        // STEP 3: Execute it!
        // This triggers sys_enter_execveat
        // Syscall number for execveat is 322 on x86_64

        let empty_path = CString::new("").unwrap();
        let argv: [*const i8; 2] = [
            name.as_ptr(), // argv[0] = name
            std::ptr::null(),
        ];
        let envp: [*const i8; 1] = [std::ptr::null()];

        // AT_EMPTY_PATH = 0x1000 (allows executing the FD directly with empty path)
        let flags = 0x1000;

        let ret = libc::syscall(
            libc::SYS_execveat,
            fd,                  // dirfd (our memfd)
            empty_path.as_ptr(), // pathname (empty)
            argv.as_ptr(),       // argv
            envp.as_ptr(),       // envp
            flags,               // flags
        );

        // If we get here, exec failed
        println!("❌ [MALWARE] execveat failed with code: {}", ret);
    }
}
