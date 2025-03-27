//! 信号处理时保存的用户上下文。

/// 处理信号时使用的栈
///
/// 详细信息见`https://man7.org/linux/man-pages/man2/sigaltstack.2.html`
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SignalStack {
    /// Base address of the stack
    pub sp: usize,
    /// Flags for the stack
    pub flags: u32,
    /// Size of the stack
    pub size: usize,
}

impl Default for SignalStack {
    fn default() -> Self {
        Self {
            sp: 0,
            // 代表SS_DISABLE，即不使用栈
            flags: super::SS_DISABLE,
            size: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
/// The `mcontext` struct for the signal action
pub struct MContext {
    pc: usize,
    gregs: [usize; 32],
    flags: usize,
    extcontext: [usize; 0],
}

impl MContext {
    fn init_by_pc(pc: usize) -> Self {
        Self {
            pc,
            gregs: [0; 32],
            flags: 0,
            extcontext: [],
        }
    }

    fn get_pc(&self) -> usize {
        self.pc
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
/// The user context saved for the signal action, which can be accessed by the signal handler
pub struct SignalUserContext {
    flags: usize,
    link: usize,
    stack: SignalStack,
    sigmask: u64,
    mcontext: MContext,
}

impl SignalUserContext {
    /// init the user context by the pc and the mask
    pub fn init(pc: usize, mask: usize) -> Self {
        Self {
            flags: 0,
            link: 0,
            stack: SignalStack::default(),
            mcontext: MContext::init_by_pc(pc),
            sigmask: mask as u64,
        }
    }

    /// get the pc from the user context
    pub fn get_pc(&self) -> usize {
        self.mcontext.get_pc()
    }
}
