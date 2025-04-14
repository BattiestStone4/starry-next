use core::ffi::c_int;

use arceos_posix_api as api;
use axerrno::LinuxResult;

use crate::ptr::{PtrWrapper, UserPtr};

pub fn sys_pipe(fds: UserPtr<[c_int; 2]>) -> LinuxResult<isize> {
    let fds = fds.get_as_mut()?;
    info!("sys_pipe <= fds: {:?}", fds);
    Ok(api::sys_pipe(fds) as _)
}
