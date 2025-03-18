#![no_std]
#![no_main]
#![doc = include_str!("../README.md")]

#[macro_use]
extern crate log;
extern crate alloc;
extern crate axstd;

mod ctypes;

mod mm;
mod ptr;
mod syscall_imp;
mod task;

use alloc::collections::VecDeque;
use alloc::{string::ToString, sync::Arc};
use axfs::api::set_current_dir;
use axhal::arch::UspaceContext;
use axstd::println;
use axsync::Mutex;
use memory_addr::VirtAddr;

#[unsafe(no_mangle)]
fn main() {
    let testcases = option_env!("AX_TESTCASES_LIST")
        .unwrap_or_else(|| "Please specify the testcases list by making user_apps")
        .split(',')
        .filter(|&x| !x.is_empty());

    println!("#### OS COMP TEST GROUP START basic-musl ####");
    for testcase in testcases {
        println!("Testing {}: ", testcase.split('/').next_back().unwrap());

        let args: VecDeque<_> = testcase.split(" ").map(|x| x.to_string()).collect();
        let mut uspace = axmm::new_user_aspace(
            VirtAddr::from_usize(axconfig::plat::USER_SPACE_BASE),
            axconfig::plat::USER_SPACE_SIZE,
        )
        .expect("Failed to create user address space");
        info!("{:?}", args);
        let (entry_vaddr, ustack_top) = mm::load_user_app(&mut (args.into()), &mut uspace).unwrap();
        let cwd = &testcase.rfind('/').map_or(testcase, |idx| &testcase[..idx]);
        info!("Set CWD to {:?}", cwd);
        let _ = set_current_dir(cwd);
        let user_task = task::spawn_user_task(
            Arc::new(Mutex::new(uspace)),
            UspaceContext::new(entry_vaddr.into(), ustack_top, 2333),
            axconfig::plat::USER_HEAP_BASE as _,
        );
        let exit_code = user_task.join();
        info!("User task {} exited with code: {:?}", testcase, exit_code);
        let _ = set_current_dir("/");
    }
    println!("#### OS COMP TEST GROUP END basic-musl ####");
}
