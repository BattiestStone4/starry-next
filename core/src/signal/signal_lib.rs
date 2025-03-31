use crate::signal::info::SigInfo;
use crate::signal::signal_no::SignalNo;
use crate::signal::ucontext::{SignalStack, SignalUserContext};
use crate::signal::{SignalHandler, SignalSet};
use crate::task::{TID2TASK, read_trapframe_from_kstack, write_trapframe_to_kstack};
use alloc::sync::Arc;
use axerrno::{LinuxError, LinuxResult};
use axhal::arch::{TrapFrame, UspaceContext};
use axtask::{TaskExtRef, current};
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

pub fn send_signal_to_task(pid: isize, signum: isize, info: Option<SigInfo>) -> LinuxResult<()> {
    let mut tid2task = TID2TASK.lock();
    if !tid2task.contains_key(&(pid as u64)) {
        return Err(LinuxError::ESRCH);
    }
    let task = tid2task.get_mut(&(pid as u64));
    let mut signal_modules = task.unwrap().task_ext().signal_modules.lock();
    let signal_module = signal_modules.get_mut(&(pid as u64)).unwrap();
    signal_module
        .signal_set
        .try_add_signal(signum as usize, info);
    Ok(())
}

#[unsafe(no_mangle)]
pub fn load_trap_for_signal() -> bool {
    let current_task = current();

    let mut signal_modules = current_task.task_ext().signal_modules.lock();
    let signal_module = signal_modules.get_mut(&current_task.id().as_u64()).unwrap();
    if let Some(old_trap_frame) = signal_module.last_trap_frame_for_signal.take() {
        unsafe {
            // let now_trap_frame: *mut TrapFrame = current_task.get_first_trap_frame();
            let now_trap_frame =
                read_trapframe_from_kstack(current_task.get_kernel_stack_top().unwrap());
            let mut now_uctx = UspaceContext::from(&now_trap_frame);
            // 考虑当时调用信号处理函数时，sp对应的地址上的内容即是SignalUserContext
            // 此时认为一定通过sig_return调用这个函数
            // 所以此时sp的位置应该是SignalUserContext的位置
            let sp = now_uctx.get_sp();
            now_uctx = UspaceContext::from(&old_trap_frame);
            if signal_module.sig_info {
                let pc = (*(sp as *const SignalUserContext)).get_pc();
                now_uctx.set_ip(pc);
            }
            write_trapframe_to_kstack(
                current_task.get_kernel_stack_top().unwrap(),
                &now_trap_frame,
            );
        }
        true
    } else {
        false
    }
}

pub fn signal_return() -> isize {
    if load_trap_for_signal() {
        // 说明确实存在着信号处理函数的trap上下文
        // 此时内核栈上存储的是调用信号处理前的trap上下文
        UspaceContext::from(&read_trapframe_from_kstack(
            current().get_kernel_stack_top().unwrap(),
        ))
        .set_retval(0);
        0
    } else {
        // 没有进行信号处理，但是调用了sig_return
        // 此时直接返回-1
        -1
    }
}
