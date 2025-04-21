use core::ffi::c_void;

use axerrno::LinuxResult;
use axsignal::ctypes::SignalSet;
use axtask::{current, TaskExtRef};
use crate::ptr::{UserConstPtr, UserPtr};

pub fn sys_rt_sigprocmask(
    _how: i32,
    _set: UserConstPtr<SignalSet>,
    _oldset: UserPtr<SignalSet>,
    _sigsetsize: usize,
) -> LinuxResult<isize> {
    // let curr = current();
    // 
    // let mut blocked = curr.task_ext().get_signal().sig_blocked;
    // 
    // if let Some(oldset) = nullable!(oldset.)
    Ok(0)
}

pub fn sys_rt_sigaction(
    _signum: i32,
    _act: UserConstPtr<c_void>,
    _oldact: UserPtr<c_void>,
    _sigsetsize: usize,
) -> LinuxResult<isize> {
    warn!("sys_rt_sigaction: not implemented");
    Ok(0)
}

pub fn sys_rt_sigtimedwait() -> LinuxResult<isize> {
    warn!("sys_rt_sigtimedwait: not implemented");
    Ok(0)
}
