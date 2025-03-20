use crate::ctypes::{SIGSET_SIZE_IN_BYTE, SigMaskFlag};
use crate::ptr::{PtrWrapper, UserConstPtr, UserPtr};
use crate::syscall_imp::signal::{
    SignalHandler, SignalSet, signal_no::SignalNo, ucontext::SignalStack,
};
use alloc::sync::Arc;
use axerrno::{LinuxError, LinuxResult};
use axhal::arch::TrapFrame;
use axtask::{TaskExtRef, current};
use core::ffi::{c_int, c_void};
use spin::Mutex;

pub struct SignalModule {
    /// 是否存在siginfo
    pub sig_info: bool,
    /// 保存的trap上下文
    pub last_trap_frame_for_signal: Option<TrapFrame>,
    /// 信号处理函数集
    pub signal_handler: Arc<Mutex<SignalHandler>>,
    /// 未决信号集
    pub signal_set: SignalSet,
    /// exit signal
    exit_signal: Option<SignalNo>,
    /// Alternative signal stack
    pub alternate_stack: SignalStack,
}

impl SignalModule {
    /// 初始化信号模块
    pub fn init_signal(signal_handler: Option<Arc<Mutex<SignalHandler>>>) -> Self {
        let signal_handler =
            signal_handler.unwrap_or_else(|| Arc::new(Mutex::new(SignalHandler::new())));
        let signal_set = SignalSet::new();
        let last_trap_frame_for_signal = None;
        let sig_info = false;
        Self {
            sig_info,
            last_trap_frame_for_signal,
            signal_handler,
            signal_set,
            exit_signal: None,
            alternate_stack: SignalStack::default(),
        }
    }

    /// Judge whether the signal request the interrupted syscall to restart
    ///
    /// # Return
    /// - None: There is no siganl need to be delivered
    /// - Some(true): The interrupted syscall should be restarted
    /// - Some(false): The interrupted syscall should not be restarted
    pub fn have_restart_signal(&self) -> Option<bool> {
        self.signal_set.find_signal().map(|sig_num| {
            self.signal_handler
                .lock()
                .get_action(sig_num)
                .need_restart()
        })
    }

    /// Set the exit signal
    pub fn set_exit_signal(&mut self, signal: SignalNo) {
        self.exit_signal = Some(signal);
    }

    /// Get the exit signal
    pub fn get_exit_signal(&self) -> Option<SignalNo> {
        self.exit_signal
    }
}

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
    let signum = signum;
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

pub(crate) fn sys_rt_sigtimedwait() -> LinuxResult<isize> {
    warn!("not implemented");
    Ok(0)
}
