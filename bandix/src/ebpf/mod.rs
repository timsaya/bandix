pub mod egress;
pub mod ingress;
use log::debug;

// 移除内存限制
fn remove_rlimit_memlock() {
    // 移除内存锁限制
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }
}

#[derive(Debug, Clone, Copy)]
pub enum EbpfTrafficDirection {
    Ingress = -1,
    Egress = 1,
}
