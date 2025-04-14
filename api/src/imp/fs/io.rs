use alloc::vec;
use arceos_posix_api::{self as api, File, FileLike, ctypes::mode_t, get_file_like};
use axerrno::{LinuxError, LinuxResult};
use core::ffi::{c_char, c_int, c_void};

use crate::ptr::{PtrWrapper, UserConstPtr, UserPtr, nullable};

pub fn sys_read(fd: i32, buf: UserPtr<c_void>, count: usize) -> LinuxResult<isize> {
    let buf = buf.get_as_bytes(count)?;
    Ok(api::sys_read(fd, buf, count))
}

pub fn sys_readv(fd: i32, iov: UserConstPtr<api::ctypes::iovec>, iocnt: i32) -> LinuxResult<isize> {
    debug!("sys_readv <= fd: {}", fd);
    if !(0..=1024).contains(&iocnt) {
        return Err(LinuxError::EINVAL);
    }

    let iov = iov.get_as_bytes(iocnt as _)?;
    let iovs = unsafe { core::slice::from_raw_parts(iov, iocnt as usize) };
    let mut ret = 0;
    for iov in iovs.iter() {
        let result = api::sys_read(fd, iov.iov_base, iov.iov_len);
        ret += result;
        if result < iov.iov_len as isize {
            break;
        }
    }
    Ok(ret)
}

pub fn sys_write(fd: i32, buf: UserConstPtr<c_void>, count: usize) -> LinuxResult<isize> {
    let buf = buf.get_as_bytes(count)?;
    Ok(api::sys_write(fd, buf, count))
}

pub fn sys_writev(
    fd: i32,
    iov: UserConstPtr<api::ctypes::iovec>,
    iocnt: i32,
) -> LinuxResult<isize> {
    let iov = iov.get_as_bytes(iocnt as _)?;
    unsafe { Ok(api::sys_writev(fd, iov, iocnt)) }
}

pub fn sys_openat(
    dirfd: i32,
    path: UserConstPtr<c_char>,
    flags: i32,
    modes: mode_t,
) -> LinuxResult<isize> {
    let path = path.get_as_null_terminated()?;
    Ok(api::sys_openat(dirfd, path.as_ptr(), flags, modes) as _)
}

pub fn sys_open(path: UserConstPtr<c_char>, flags: i32, modes: mode_t) -> LinuxResult<isize> {
    use arceos_posix_api::AT_FDCWD;
    sys_openat(AT_FDCWD as _, path, flags, modes)
}

pub fn sys_lseek(fd: i32, offset: isize, whence: i32) -> LinuxResult<isize> {
    Ok(api::sys_lseek(fd, offset as _, whence) as _)
}

pub fn sys_sendfile(
    out_fd: c_int,
    in_fd: c_int,
    offset: UserPtr<u64>,
    len: usize,
) -> LinuxResult<isize> {
    debug!(
        "sys_sendfile <= out_fd: {}, in_fd: {}, offset: {}, len: {}",
        out_fd,
        in_fd,
        !offset.is_null(),
        len
    );

    let src = get_file_like(in_fd)?;
    let dest = get_file_like(out_fd)?;
    let offset = nullable!(offset.get_as_mut())?;

    if let Some(offset) = offset {
        let src = src
            .into_any()
            .downcast::<File>()
            .map_err(|_| LinuxError::ESPIPE)?;

        do_sendfile(
            |buf| {
                let bytes_read = src.inner().lock().read_at(*offset, buf)?;
                *offset += bytes_read as u64;
                Ok(bytes_read)
            },
            dest.as_ref(),
        )
    } else {
        do_sendfile(|buf| src.read(buf), dest.as_ref())
    }
    .map(|n| n as _)
}

fn do_sendfile<F, D>(mut read: F, dest: &D) -> LinuxResult<usize>
where
    F: FnMut(&mut [u8]) -> LinuxResult<usize>,
    D: FileLike + ?Sized,
{
    let mut buf = vec![0; 0x1000];
    let mut total_written = 0;
    loop {
        let bytes_read = read(&mut buf)?;
        if bytes_read == 0 {
            break;
        }

        let bytes_written = dest.write(&buf[..bytes_read])?;
        if bytes_written < bytes_read {
            break;
        }
        total_written += bytes_written;
    }

    Ok(total_written)
}
