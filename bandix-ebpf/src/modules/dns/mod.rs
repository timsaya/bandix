// DNS monitoring module (预留)
// This module will handle DNS query monitoring and analysis

pub mod maps;

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    programs::TcContext,
};

#[inline(always)]
pub fn handle_dns_ingress(ctx: TcContext) -> Result<i32, ()> {
    Ok(TC_ACT_PIPE)
}

#[inline(always)]
pub fn handle_dns_egress(ctx: TcContext) -> Result<i32, ()> {
    Ok(TC_ACT_PIPE)
}
