use super::remove_rlimit_memlock;
use aya::programs::{tc, SchedClassifier, TcAttachType};

/// 加载共享的 eBPF 程序（入口和出口）
/// DNS 和流量模块共享相同的入口和出口钩子
/// 返回未包装的 eBPF 对象，以便在包装到 Arc 之前配置映射
pub async fn load_shared(iface: String) -> anyhow::Result<aya::Ebpf> {
    remove_rlimit_memlock();

    log::info!("Loading shared eBPF programs (ingress and egress) for interface {}", iface);

    // 一次性加载 eBPF 对象 - 入口和出口程序都在同一个对象中
    // 这确保它们共享相同的映射（DNS_DATA、MAC_TRAFFIC、MAC_RATE_LIMITS 等）
    let mut ebpf = aya::EbpfLoader::new()
        .load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/bandix")))
        .map_err(|e| anyhow::anyhow!("Failed to load eBPF program: {}", e))?;

    // 添加 clsact qdisc（如果尚未存在，错误是无害的）
    if let Err(e) = tc::qdisc_add_clsact(&iface) {
        log::debug!("Failed to add clsact qdisc (may already exist): {}", e);
    }

    // 加载and attach shared ingress program
    let ingress_program: &mut SchedClassifier = ebpf
        .program_mut("shared_ingress")
        .ok_or_else(|| anyhow::anyhow!("Shared ingress program not found in eBPF object"))?
        .try_into()
        .map_err(|e| anyhow::anyhow!("Failed to convert to SchedClassifier: {:?}", e))?;

    ingress_program
        .load()
        .map_err(|e| anyhow::anyhow!("Failed to load shared ingress program: {}", e))?;

    ingress_program
        .attach(&iface, TcAttachType::Ingress)
        .map_err(|e| anyhow::anyhow!("Failed to attach shared ingress program to {}: {}", iface, e))?;

    log::info!("Shared ingress program successfully attached to {}", iface);

    // 加载并附加共享出口程序
    let egress_program: &mut SchedClassifier = ebpf
        .program_mut("shared_egress")
        .ok_or_else(|| anyhow::anyhow!("Shared egress program not found in eBPF object"))?
        .try_into()
        .map_err(|e| anyhow::anyhow!("Failed to convert to SchedClassifier: {:?}", e))?;

    egress_program
        .load()
        .map_err(|e| anyhow::anyhow!("Failed to load shared egress program: {}", e))?;

    egress_program
        .attach(&iface, TcAttachType::Egress)
        .map_err(|e| anyhow::anyhow!("Failed to attach shared egress program to {}: {}", iface, e))?;

    log::info!("Shared egress program successfully attached to {}", iface);
    log::info!("Shared eBPF programs loaded and attached. DNS and traffic modules share the same ingress and egress hooks.");

    // 返回未包装的 eBPF 对象，以便在包装到 Arc 之前配置映射
    Ok(ebpf)
}
