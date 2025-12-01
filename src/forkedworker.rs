
pub struct ForkedWorker {
    pub pid: libc::pid_t
}

impl ForkedWorker {
    pub fn new<T>(func: T) -> Result<ForkedWorker,()>
    where T: FnOnce() -> i32 {
        let pid = unsafe { libc::fork() };
        if (pid < 0) {
            return Err(());
        }
        if (pid == 0) {
            let ret = func();
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
