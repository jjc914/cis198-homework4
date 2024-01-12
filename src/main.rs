// Modules for this assignment
// (You only need to edit args.rs and main.rs)
mod args;
mod system_call_names;
pub mod util;

// The command line struct from args.rs
use args::Opt;

// These are the functions that you will need from nix and std:
use nix::sys::ptrace;
use nix::sys::signal::{raise, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult};
use nix::unistd::Pid;
// use std::collections::HashMap;
use std::collections::HashSet;
use std::error::Error;
use std::ffi::CString;

use structopt::StructOpt;

fn main() -> Result<(), Box<dyn Error>> {
    let opt = Opt::from_args();
    opt.validate()?;

    let syscalls = opt.syscalls_to_trace();
    match unsafe{fork()} {
        Ok(ForkResult::Parent { child, .. }) => {
            run_tracer(child, &syscalls);
        },
        Ok(ForkResult::Child) => {
            run_tracee(opt.exe, opt.exe_args);
        },
        Err(_) => panic!("fork failed"),
    }
    Ok(())
}

// Code to be executed by the tracee (child process)
#[allow(dead_code)]
fn run_tracee(exe: String, exe_args: Vec<String>) -> nix::Result<()> {
    ptrace::traceme()?;
    raise(Signal::SIGSTOP)?;

    let exe_cstr = CString::new(exe).unwrap();
    let mut exe_args_cstr_vec = Vec::new();
    for arg in exe_args {
        exe_args_cstr_vec.push(CString::new(arg).unwrap());
    }
    let exe_args_cstr = &exe_args_cstr_vec[..];
    execvp(&exe_cstr, exe_args_cstr)?;
    Ok(())
}

// Code to be executed by the tracer (parent process)
#[allow(dead_code)]
fn run_tracer(
    child_pid: Pid,
    syscalls_to_trace: &HashSet<&str>,
) -> nix::Result<()> {
    waitpid(child_pid, None)?;

    let options = util::ptrace_set_options(child_pid);
    ptrace::cont(child_pid, None);

    let mut pre_syscall = true;
    loop {
        let actual_pid = match waitpid(None, None).unwrap() {
            WaitStatus::Exited(pid, _) => {
                break;
            },
            WaitStatus::PtraceEvent(pid, _, _) => pid,
            WaitStatus::Stopped(pid, _) => pid,
            WaitStatus::Signaled(pid, _, _) => pid,
            WaitStatus::PtraceSyscall(pid) => {
                let regs = util::get_regs(pid);
                let name = util::extract_syscall_name(regs);
                if pre_syscall {
                    util::handle_pre_syscall(regs, name, pid);
                } else {
                    util::handle_post_syscall(regs, name, pid);
                }
                pid
            },
            WaitStatus::Continued(pid) => pid,
            WaitStatus::StillAlive => {
                panic!("");
            },
        };

        ptrace::syscall(actual_pid, None)?;
        pre_syscall = !pre_syscall;
    }
    Ok(())
}
