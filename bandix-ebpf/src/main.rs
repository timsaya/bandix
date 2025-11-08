#![no_std]
#![no_main]

mod modules;
mod utils;

use aya_ebpf::bindings::TC_ACT_PIPE;
use aya_ebpf::macros::classifier;
use aya_ebpf::programs::TcContext;

use modules::dns::{handle_dns_egress, handle_dns_ingress};
use modules::traffic::{handle_traffic_egress, handle_traffic_ingress};

#[classifier]
pub fn traffic_ingress(ctx: TcContext) -> i32 {
    match handle_traffic_ingress(ctx) {
        Ok(ret) => ret,
        _ => TC_ACT_PIPE,
    }
}

#[classifier]
pub fn traffic_egress(ctx: TcContext) -> i32 {
    match handle_traffic_egress(ctx) {
        Ok(ret) => ret,
        _ => TC_ACT_PIPE,
    }
}

#[classifier]
pub fn dns_ingress(ctx: TcContext) -> i32 {
    match handle_dns_ingress(ctx) {
        Ok(ret) => ret,
        _ => TC_ACT_PIPE,
    }
}

#[classifier]
pub fn dns_egress(ctx: TcContext) -> i32 {
    match handle_dns_egress(ctx) {
        Ok(ret) => ret,
        _ => TC_ACT_PIPE,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
