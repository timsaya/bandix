use super::remove_rlimit_memlock;
use aya::programs::tc::{self, NlOptions, SchedClassifier, TcAttachOptions, TcAttachType};
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
/// * `tc_priority` - TC filter 优先级（0 表示使用内核默认值）
pub async fn load_shared(iface: String, tc_priority: u16) -> anyhow::Result<aya::Ebpf> {
    remove_rlimit_memlock();

    log::info!(
        "Loading shared eBPF programs for interface {} with TC priority {}",
        iface,
        if tc_priority == 0 { "auto".to_string() } else { tc_priority.to_string() }
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

    // 根据 tc_priority 选择 attach 方式
    if tc_priority > 0 {
        let nl_options = NlOptions {
            priority: tc_priority,
            handle: 0, // 让系统自动分配 handle
        };
        ingress_program
            .attach_with_options(&iface, TcAttachType::Ingress, TcAttachOptions::Netlink(nl_options))
            .map_err(|e| anyhow::anyhow!("Failed to attach shared ingress program to {}: {}", iface, e))?;
    } else {
        // tc_priority == 0: 使用默认行为（内核自动分配优先级）
        ingress_program
            .attach(&iface, TcAttachType::Ingress)
            .map_err(|e| anyhow::anyhow!("Failed to attach shared ingress program to {}: {}", iface, e))?;
    }

    log::info!("Shared ingress program successfully attached to {}", iface);

    // 加载并附加共享出口程序
    let egress_program: &mut SchedClassifier = ebpf
        .program_mut("shared_egress")
        .ok_or_else(|| anyhow::anyhow!("Shared egress program not found in eBPF object"))?
        .try_into()
        .map_err(|e| anyhow::anyhow!("Failed to convert to SchedClassifier: {:?}", e))?;

    load_program_with_retry(egress_program, "shared_egress")?;

    // 根据 tc_priority 选择 attach 方式
    if tc_priority > 0 {
        let nl_options = NlOptions {
            priority: tc_priority,
            handle: 0,
        };
        egress_program
            .attach_with_options(&iface, TcAttachType::Egress, TcAttachOptions::Netlink(nl_options))
            .map_err(|e| anyhow::anyhow!("Failed to attach shared egress program to {}: {}", iface, e))?;
    } else {
        egress_program
            .attach(&iface, TcAttachType::Egress)
            .map_err(|e| anyhow::anyhow!("Failed to attach shared egress program to {}: {}", iface, e))?;
    }

    log::info!("Shared egress program successfully attached to {}", iface);
    log::info!(
        "Shared eBPF programs loaded and attached. DNS and traffic modules share the same ingress and egress hooks."
    );

    // 返回未包装的 eBPF 对象，以便在包装到 Arc 之前配置映射
    Ok(ebpf)
}
