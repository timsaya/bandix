use super::remove_rlimit_memlock;
use aya::programs::{LinkOrder, ProgramId};
use aya::programs::tc::{self, NlOptions, SchedClassifier, TcAttachOptions, TcAttachType};
use crate::command::{TcBackend, TcOrder};
use std::time::Duration;

const MAX_LOAD_RETRIES: u32 = 3;
const RETRY_DELAY_SECS: u64 = 3;

fn load_program_with_retry(program: &mut SchedClassifier, name: &str) -> anyhow::Result<()> {
    let mut last_err = None;
    for attempt in 1..=MAX_LOAD_RETRIES {
        match program.load() {
            Ok(()) => return Ok(()),
            Err(e) => {
                log::warn!("Failed to load {} (attempt {}/{}): {}", name, attempt, MAX_LOAD_RETRIES, e);
                last_err = Some(e);
                if attempt < MAX_LOAD_RETRIES {
                    std::thread::sleep(Duration::from_secs(RETRY_DELAY_SECS));
                }
            }
        }
    }
    Err(anyhow::anyhow!("Failed to load {} after {} retries: {}", name, MAX_LOAD_RETRIES, last_err.unwrap()))
}

/// 加载共享的 eBPF 程序（入口和出口）
/// DNS 和流量模块共享相同的入口和出口钩子
/// 返回未包装的 eBPF 对象，以便在包装到 Arc 之前配置映射
///
/// # Arguments
/// * `iface` - 要监控的网络接口名称
fn kernel_at_least(major: u32, minor: u32, patch: u32) -> bool {
    let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") else {
        return false;
    };
    let mut parts = release.trim().splitn(3, |c: char| c == '.' || c == '-');
    let (maj, min, pat): (u32, u32, u32) = (
        parts.next().and_then(|p| p.parse().ok()).unwrap_or(0),
        parts.next().unwrap_or("0").parse().unwrap_or(0),
        parts
            .next()
            .unwrap_or("0")
            .split('-')
            .next()
            .unwrap_or("0")
            .parse()
            .unwrap_or(0),
    );
    (maj, min, pat) >= (major, minor, patch)
}

/// * `tc_order` - TC 挂载顺序（first/default/last）
pub async fn load_shared(
    iface: String,
    tc_order: TcOrder,
    tc_backend: TcBackend,
    netlink_priority: Option<u16>,
    tcx_anchor_ingress_id: Option<u32>,
    tcx_anchor_egress_id: Option<u32>,
) -> anyhow::Result<aya::Ebpf> {
    remove_rlimit_memlock();

    let kernel_supports_tcx = kernel_at_least(6, 6, 0);
    let use_tcx = match tc_backend {
        TcBackend::Auto => kernel_supports_tcx,
        TcBackend::Tcx => {
            if !kernel_supports_tcx {
                anyhow::bail!("--tc-backend=tcx requires kernel >= 6.6.0");
            }
            true
        }
        TcBackend::Netlink => false,
    };
    if use_tcx && netlink_priority.is_some() {
        anyhow::bail!("--netlink-priority is only valid for netlink backend");
    }
    if !use_tcx && matches!(tc_order, TcOrder::Before | TcOrder::After) {
        anyhow::bail!("--tc-order=before/after is not supported by netlink backend");
    }
    let order_str = match tc_order {
        TcOrder::First => "first",
        TcOrder::Default => "default",
        TcOrder::Last => "last",
        TcOrder::Before => "before",
        TcOrder::After => "after",
    };
    let backend_req_str = match tc_backend {
        TcBackend::Auto => "auto",
        TcBackend::Tcx => "tcx",
        TcBackend::Netlink => "netlink",
    };

    log::info!(
        "Loading shared eBPF programs for interface {} with TC order {} (requested backend: {}, resolved backend: {})",
        iface,
        order_str,
        backend_req_str,
        if use_tcx { "tcx" } else { "netlink" }
    );

    let mut ebpf = aya::EbpfLoader::new()
        .load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/bandix")))
        .map_err(|e| anyhow::anyhow!("Failed to load eBPF program: {}", e))?;

    if let Err(e) = tc::qdisc_add_clsact(&iface) {
        log::debug!("Failed to add clsact qdisc (may already exist): {}", e);
    }

    let ingress_program: &mut SchedClassifier = ebpf
        .program_mut("shared_ingress")
        .ok_or_else(|| anyhow::anyhow!("Shared ingress program not found in eBPF object"))?
        .try_into()
        .map_err(|e| anyhow::anyhow!("Failed to convert to SchedClassifier: {:?}", e))?;

    load_program_with_retry(ingress_program, "shared_ingress")?;

    let opts = |attach_type: TcAttachType| -> anyhow::Result<TcAttachOptions> {
        if use_tcx {
            let anchor_program_id = match attach_type {
                TcAttachType::Ingress => tcx_anchor_ingress_id,
                TcAttachType::Egress => tcx_anchor_egress_id,
                _ => None,
            };
            let order = match tc_order {
                TcOrder::First => LinkOrder::first(),
                TcOrder::Default => LinkOrder::default(),
                TcOrder::Last => LinkOrder::last(),
                TcOrder::Before => {
                    let id = anchor_program_id.ok_or_else(|| {
                        anyhow::anyhow!(
                            "anchor program id is required for {:?} when --tc-order=before; use --tcx-anchor-ingress-id/--tcx-anchor-egress-id",
                            attach_type
                        )
                    })?;
                    // SAFETY: program id validity is checked by kernel at attach time.
                    LinkOrder::before_program_id(unsafe { ProgramId::new(id) })
                }
                TcOrder::After => {
                    let id = anchor_program_id.ok_or_else(|| {
                        anyhow::anyhow!(
                            "anchor program id is required for {:?} when --tc-order=after; use --tcx-anchor-ingress-id/--tcx-anchor-egress-id",
                            attach_type
                        )
                    })?;
                    // SAFETY: program id validity is checked by kernel at attach time.
                    LinkOrder::after_program_id(unsafe { ProgramId::new(id) })
                }
            };
            Ok(TcAttachOptions::TcxOrder(order))
        } else {
            let nl_priority = if let Some(v) = netlink_priority {
                v
            } else {
                match tc_order {
                    TcOrder::First => 1u16,
                    TcOrder::Default => 0u16,
                    TcOrder::Last => 65535u16,
                    TcOrder::Before | TcOrder::After => {
                        anyhow::bail!("--tc-order=before/after is not supported by netlink backend");
                    }
                }
            };
            Ok(TcAttachOptions::Netlink(NlOptions {
                priority: nl_priority,
                handle: 0,
            }))
        }
    };
    ingress_program
        .attach_with_options(&iface, TcAttachType::Ingress, opts(TcAttachType::Ingress)?)
        .map_err(|e| anyhow::anyhow!("Failed to attach shared ingress program to {}: {}", iface, e))?;

    log::info!("Shared ingress program successfully attached to {}", iface);

    // 加载并附加共享出口程序
    let egress_program: &mut SchedClassifier = ebpf
        .program_mut("shared_egress")
        .ok_or_else(|| anyhow::anyhow!("Shared egress program not found in eBPF object"))?
        .try_into()
        .map_err(|e| anyhow::anyhow!("Failed to convert to SchedClassifier: {:?}", e))?;

    load_program_with_retry(egress_program, "shared_egress")?;

    egress_program
        .attach_with_options(&iface, TcAttachType::Egress, opts(TcAttachType::Egress)?)
        .map_err(|e| anyhow::anyhow!("Failed to attach shared egress program to {}: {}", iface, e))?;

    log::info!("Shared egress program successfully attached to {}", iface);
    log::info!(
        "Shared eBPF programs loaded and attached. DNS and traffic modules share the same ingress and egress hooks."
    );
    log::info!(
        "TC backend options: {}",
        if use_tcx {
            format!(
                "tcx_anchor_ingress_id={},tcx_anchor_egress_id={}",
                tcx_anchor_ingress_id
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                tcx_anchor_egress_id
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none".to_string())
            )
        } else {
            format!(
                "netlink_priority={}",
                netlink_priority
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "derived_from_order".to_string())
            )
        }
    );

    // 返回未包装的 eBPF 对象，以便在包装到 Arc 之前配置映射
    Ok(ebpf)
}
