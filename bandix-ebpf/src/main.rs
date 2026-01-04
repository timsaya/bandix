#![no_std]
#![no_main]

mod modules;
mod utils;

use aya_ebpf::bindings::{TC_ACT_PIPE, TC_ACT_SHOT};
use aya_ebpf::macros::classifier;
use aya_ebpf::programs::TcContext;

use crate::utils::{is_dns_enabled, is_traffic_enabled};
use modules::dns::{handle_dns_egress, handle_dns_ingress};
use modules::traffic::{handle_traffic_egress, handle_traffic_ingress};

#[inline(always)]
fn process_module_result(result: Result<i32, ()>) -> Option<i32> {
    match result {
        Ok(TC_ACT_SHOT) => Some(TC_ACT_SHOT),
        Ok(ret) if ret != TC_ACT_PIPE => Some(ret),
        _ => None,
    }
}

#[classifier]
pub fn shared_ingress(ctx: TcContext) -> i32 {
    if is_traffic_enabled() {
        if let Some(result) = process_module_result(handle_traffic_ingress(&ctx)) {
            return result;
        }
    }

    if is_dns_enabled() {
        if let Some(result) = process_module_result(handle_dns_ingress(&ctx)) {
            return result;
        }
    }

    TC_ACT_PIPE
}

#[classifier]
pub fn shared_egress(ctx: TcContext) -> i32 {
    if is_traffic_enabled() {
        if let Some(result) = process_module_result(handle_traffic_egress(&ctx)) {
            return result;
        }
    }

    if is_dns_enabled() {
        if let Some(result) = process_module_result(handle_dns_egress(&ctx)) {
            return result;
        }
    }

    TC_ACT_PIPE
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    panic!("Panic in eBPF program");
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
