#![no_std]
#![no_main]
#![feature(core_intrinsics)]

mod modules;
mod utils;

use aya_ebpf::bindings::TC_ACT_UNSPEC;
use aya_ebpf::macros::classifier;
use aya_ebpf::programs::TcContext;

use crate::utils::{is_dns_enabled, is_traffic_enabled};
use modules::dns::{handle_dns_egress, handle_dns_ingress};
use modules::traffic::{handle_traffic_egress, handle_traffic_ingress};

#[classifier]
pub fn shared_ingress(ctx: TcContext) -> i32 {
    if is_traffic_enabled() {
        let result = handle_traffic_ingress(&ctx).unwrap_or(TC_ACT_UNSPEC);
        if result != TC_ACT_UNSPEC {
            return result;
        }
    }

    if is_dns_enabled() {
        let result = handle_dns_ingress(&ctx).unwrap_or(TC_ACT_UNSPEC);
        if result != TC_ACT_UNSPEC {
            return result;
        }
    }

    TC_ACT_UNSPEC
}

#[classifier]
pub fn shared_egress(ctx: TcContext) -> i32 {
    if is_traffic_enabled() {
        let result = handle_traffic_egress(&ctx).unwrap_or(TC_ACT_UNSPEC);
        if result != TC_ACT_UNSPEC {
            return result;
        }
    }

    if is_dns_enabled() {
        let result = handle_dns_egress(&ctx).unwrap_or(TC_ACT_UNSPEC);
        if result != TC_ACT_UNSPEC {
            return result;
        }
    }

    TC_ACT_UNSPEC
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    panic!("Panic in eBPF program");
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
