use std::{ffi::CString, fs::File, io::Write, os::unix::io::FromRawFd, ptr};

fn main() {
    unsafe {
        println!("🧪 [SIMULATION] Starting Reflective Loading (mmap) test...");

        // 1. Create the anonymous file (memfd)
        // This triggers sys_enter_memfd_create
        let name = CString::new("libmalware.so").unwrap();
        let fd = libc::memfd_create(name.as_ptr(), 0);

        if fd < 0 {
            panic!("Failed to create memfd!");
        }
        println!("😈 [STEP 1] Created anonymous memfd: FD {}", fd);

        // 2. Write "Payload"
        // In a real attack, this would be an ELF binary.
        // For detection testing, dummy bytes work fine.
        let mut file = File::from_raw_fd(fd);
        let payload = vec![0x90; 4096]; // NOP sled (dummy data)
        file.write_all(&payload).unwrap();

        // Forget file so FD stays open
        std::mem::forget(file);
        println!("😈 [STEP 2] Payload written to memory.");

        // 3. Load it into memory as EXECUTABLE
        // This triggers sys_enter_mmap with PROT_EXEC (0x4)
        println!("😈 [STEP 3] Mapping memory with PROT_EXEC...");

        let addr = libc::mmap(
            ptr::null_mut(),                   // Address (kernel chooses)
            4096,                              // Length
            libc::PROT_READ | libc::PROT_EXEC, // 🚨 THE RED FLAG
            libc::MAP_PRIVATE,                 // Flags
            fd,                                // The memfd FD
            0,                                 // Offset
        );

        if addr == libc::MAP_FAILED {
            panic!("mmap failed!");
        }

        println!("✅ [SUCCESS] Payload mapped at address: {:?}", addr);
        println!("   (Sentinel should have alerted by now)");

        // Clean up (optional, OS cleans up on exit)
        libc::munmap(addr, 4096);
        libc::close(fd);
    }
}
