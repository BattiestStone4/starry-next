use crate::ptr::{PtrWrapper, UserConstPtr, UserPtr};
use axerrno::{LinuxError, LinuxResult};
use axhal::cpu::this_cpu_id;
use axtask::{TaskExtRef, current};
use core::ffi::{c_int, c_void};
use starry_core::ctypes::{SIGSET_SIZE_IN_BYTE, SigMaskFlag};
use starry_core::signal::signal_lib::{send_signal_to_task, signal_return};
use starry_core::signal::signal_no::SignalNo;

pub fn sys_rt_sigprocmask(
    how: c_int,
    set: UserConstPtr<c_void>,
    oldset: UserPtr<c_void>,
    sigsetsize: usize,
) -> LinuxResult<isize> {
    let flag = SigMaskFlag::from(how as usize);
    let new_mask: *const usize = set.address().as_ptr_of();
    let old_mask: *mut usize = oldset.address().as_mut_ptr_of();
    if sigsetsize != SIGSET_SIZE_IN_BYTE {
        // 若sigsetsize不是正确的大小，则返回错误
        return Err(LinuxError::EINVAL);
    }

    let current_task = current();

    let mut signal_modules = current_task.task_ext().signal_modules.lock();
    let signal_module = signal_modules.get_mut(&current_task.id().as_u64()).unwrap();
    if old_mask as usize != 0 {
        unsafe {
            *old_mask = signal_module.signal_set.mask;
        }
    }

    if new_mask as usize != 0 {
        let now_mask = unsafe { *new_mask };
        match flag {
            SigMaskFlag::Block => {
                signal_module.signal_set.mask |= now_mask;
            }
            SigMaskFlag::Unblock => {
                signal_module.signal_set.mask &= !now_mask;
            }
            SigMaskFlag::Setmask => {
                signal_module.signal_set.mask = now_mask;
            }
        }
    }
    Ok(0)
}

pub fn sys_rt_sigaction(
    signum: i32,
    act: UserConstPtr<c_void>,
    oldact: UserPtr<c_void>,
    _sigsetsize: usize,
) -> LinuxResult<isize> {
    let action = act.address().as_ptr_of();
    let old_action = oldact.address().as_mut_ptr_of();
    info!(
        "signum: {}, action: {:x}, old_action: {:x}",
        signum, action as usize, old_action as usize
    );
    if signum == SignalNo::SIGKILL as c_int || signum == SignalNo::SIGSTOP as c_int {
        // 特殊参数不能被覆盖
        return Err(LinuxError::EPERM);
    }

    let current_task = current();
    let mut signal_modules = current_task.task_ext().signal_modules.lock();
    let signal_module = signal_modules.get_mut(&current_task.id().as_u64()).unwrap();
    let mut signal_handler = signal_module.signal_handler.lock();
    let old_address = old_action as usize;

    if old_address != 0 {
        // 将原有的action存储到old_address
        unsafe {
            *old_action = *signal_handler.get_action(signum as usize);
        }
    }
    let new_address = action as usize;
    if new_address != 0 {
        unsafe { signal_handler.set_action(signum as usize, action) };
    }
    Ok(0)
}

pub fn sys_rt_sigtimedwait() -> LinuxResult<isize> {
    warn!("not implemented");
    Ok(0)
}

/// 向pid指定的进程发送信号
///
/// 由于处理信号的单位在线程上，所以若进程中有多个线程，则会发送给主线程
/// # Arguments
/// * `pid` - isize
/// * `signum` - isize
pub fn sys_kill(pid: isize, signum: isize) -> LinuxResult<isize> {
    if pid > 0 && signum > 0 {
        // 不关心是否成功
        let _ = send_signal_to_task(pid, signum, None);
        Ok(0)
    } else if pid == 0 {
        Err(LinuxError::ESRCH)
    } else {
        Err(LinuxError::EINVAL)
    }
}

/// 向tid指定的线程发送信号
/// # Arguments
/// * `tid` - isize
/// * `signum` - isize
pub fn sys_tkill(tid: isize, signum: isize) -> LinuxResult<isize> {
    info!(
        "cpu: {}, send signal: {} to: {}",
        this_cpu_id(),
        signum,
        tid
    );
    if tid > 0 && signum > 0 {
        let _ = send_signal_to_task(tid, signum, None);
        Ok(0)
    } else {
        Err(LinuxError::EINVAL)
    }
}

/// 向tid指定的线程组发送信号
pub fn sys_tgkill(tgid: isize, tid: isize, signum: isize) -> LinuxResult<isize> {
    info!(
        "cpu: {}, send singal: {} to: {}",
        this_cpu_id(),
        signum,
        tid
    );
    if tgid > 0 && tid > 0 && signum > 0 {
        let _ = send_signal_to_task(tid, signum, None);
        Ok(0)
    } else {
        Err(LinuxError::EINVAL)
    }
}

pub fn sys_rt_sigreturn() -> LinuxResult<isize> {
    Ok(signal_return())
}
