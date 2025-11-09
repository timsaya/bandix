#![no_std]
#![no_main]

mod modules;
mod utils;

use aya_ebpf::bindings::{TC_ACT_PIPE, TC_ACT_SHOT};
use aya_ebpf::macros::classifier;
use aya_ebpf::programs::TcContext;

use modules::dns::{handle_dns_egress, handle_dns_ingress};
use modules::traffic::{handle_traffic_egress, handle_traffic_ingress};
use crate::utils::{is_traffic_enabled, is_dns_enabled};

/// Shared ingress hook: handles both traffic and DNS monitoring
/// Traffic module processes all IP packets, DNS module processes DNS packets only
/// Module enable/disable is controlled by MODULE_ENABLE_FLAGS map
#[classifier]
pub fn shared_ingress(ctx: TcContext) -> i32 {
    // Check module enable flags using volatile read
    let traffic_enabled = is_traffic_enabled();
    let dns_enabled = is_dns_enabled();
    
    // Handle traffic monitoring if enabled
    let traffic_result = if traffic_enabled {
        handle_traffic_ingress(&ctx)
    } else {
        Ok(TC_ACT_PIPE) // Traffic disabled, pass through
    };
    
    // If traffic module wants to drop the packet, do so immediately
    match traffic_result {
        Ok(TC_ACT_SHOT) => {
            // Packet should be dropped, don't process DNS
            return TC_ACT_SHOT;
        }
        Ok(ret) if ret != TC_ACT_PIPE => {
            // Traffic module returned something other than TC_ACT_PIPE or TC_ACT_SHOT
            // Process DNS if enabled, but return the traffic result
            if dns_enabled {
                let _ = handle_dns_ingress(&ctx);
            }
            return ret;
        }
        _ => {
            // Traffic allowed (TC_ACT_PIPE) or error, continue to DNS processing if enabled
        }
    }
    
    // Handle DNS monitoring if enabled (only processes DNS packets, returns TC_ACT_PIPE for non-DNS)
    if dns_enabled {
        match handle_dns_ingress(&ctx) {
            Ok(ret) => ret,
            _ => TC_ACT_PIPE,
        }
    } else {
        TC_ACT_PIPE // DNS disabled, pass through
    }
}

/// Shared egress hook: handles both traffic and DNS monitoring
/// Traffic module processes all IP packets, DNS module processes DNS packets only
/// Module enable/disable is controlled by MODULE_ENABLE_FLAGS map
#[classifier]
pub fn shared_egress(ctx: TcContext) -> i32 {
    // Check module enable flags using volatile read
    let traffic_enabled = is_traffic_enabled();
    let dns_enabled = is_dns_enabled();
    
    // Handle traffic monitoring if enabled
    let traffic_result = if traffic_enabled {
        handle_traffic_egress(&ctx)
    } else {
        Ok(TC_ACT_PIPE) // Traffic disabled, pass through
    };
    
    // If traffic module wants to drop the packet, do so immediately
    match traffic_result {
        Ok(TC_ACT_SHOT) => {
            // Packet should be dropped, don't process DNS
            return TC_ACT_SHOT;
        }
        Ok(ret) if ret != TC_ACT_PIPE => {
            // Traffic module returned something other than TC_ACT_PIPE or TC_ACT_SHOT
            // Process DNS if enabled, but return the traffic result
            if dns_enabled {
                let _ = handle_dns_egress(&ctx);
            }
            return ret;
        }
        _ => {
            // Traffic allowed (TC_ACT_PIPE) or error, continue to DNS processing if enabled
        }
    }
    
    // Handle DNS monitoring if enabled (only processes DNS packets, returns TC_ACT_PIPE for non-DNS)
    if dns_enabled {
        match handle_dns_egress(&ctx) {
            Ok(ret) => ret,
            _ => TC_ACT_PIPE,
        }
    } else {
        TC_ACT_PIPE // DNS disabled, pass through
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    panic!("Panic in eBPF program");
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
