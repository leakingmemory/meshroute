
pub struct ForkedWorker {
    pub pid: libc::pid_t
}

impl ForkedWorker {
    pub fn new_from_pid(pid: libc::pid_t) -> Self {
        Self { pid }
    }
    pub fn new<T>(func: T) -> Result<ForkedWorker,()>
    where T: FnOnce() -> i32 {
        println!("Forking");
        let pid = unsafe { libc::fork() };
        println!("Fork returned {}", pid);
        if (pid < 0) {
            return Err(());
        }
        if (pid == 0) {
            println!("Run func");
            let ret = func();
            println!("Done child");
            std::process::exit(ret);
        }
        Ok(ForkedWorker { pid })
    }
}

impl Drop for ForkedWorker {
    fn drop(&mut self) {
        if self.pid > 0 {
            let _ = unsafe { libc::kill(self.pid, libc::SIGTERM) };
            let _ = unsafe { libc::waitpid(self.pid, std::ptr::null_mut(), 0) };
        }
        self.pid = -1;
    }
}
