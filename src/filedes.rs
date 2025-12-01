
pub struct FileDes {
    fd: libc::c_int
}

impl FileDes {
    pub fn new() -> FileDes {
        FileDes { fd: -1 }
    }
    pub fn open(name: &str, flags: libc::c_int, mode: libc::c_int) -> FileDes {
        let name = format!("{}\0", name);
        FileDes {
            fd: unsafe { libc::open(name.as_ptr() as *const libc::c_char, flags, mode) }
        }
    }
    pub fn close(&mut self) -> bool {
        if self.fd < 0 {
            return true;
        }
        if unsafe { libc::close(self.fd) } == 0 {
            self.fd = -1;
            return true;
        }
        false
    }
    pub unsafe fn ioctl<T>(&self, request: libc::c_ulong, arg: T) -> Result<libc::c_int, libc::c_int> {
        let r = unsafe { libc::ioctl(self.fd, request, arg) };
        if r >= 0 {
            Ok(r)
        } else {
            Err(r)
        }
    }
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, libc::ssize_t> {
        let r = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as libc::size_t) };
        if r >= 0 {
            let n = r as usize;
            Ok(n)
        } else {
            Err(r)
        }
    }
}

impl Drop for FileDes {
    fn drop(&mut self) {
        self.close();
    }
}
