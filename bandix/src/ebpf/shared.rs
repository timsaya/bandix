use super::remove_rlimit_memlock;
use aya::programs::{tc, SchedClassifier, TcAttachType};

/// Load shared eBPF programs (ingress and egress)
/// Both DNS and traffic modules share the same ingress and egress hooks
/// Returns unwrapped eBPF object so maps can be configured before wrapping in Arc
pub async fn load_shared(iface: String) -> anyhow::Result<aya::Ebpf> {
    remove_rlimit_memlock();

    log::info!("Loading shared eBPF programs (ingress and egress) for interface: {}", iface);

    // Load eBPF object once - both ingress and egress programs are in the same object
    // This ensures they share the same maps (DNS_DATA, MAC_TRAFFIC, MAC_RATE_LIMITS, etc.)
    let mut ebpf = aya::EbpfLoader::new()
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/bandix"
        )))
        .map_err(|e| anyhow::anyhow!("Failed to load eBPF program: {}", e))?;

    // Add clsact qdisc (if not already present, error is harmless)
    if let Err(e) = tc::qdisc_add_clsact(&iface) {
        log::debug!("Failed to add clsact qdisc (may already exist): {}", e);
    }

    // Load and attach shared ingress program
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

    log::info!("Shared ingress program attached successfully to {}", iface);

    // Load and attach shared egress program
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

    log::info!("Shared egress program attached successfully to {}", iface);
    log::info!("Shared eBPF programs loaded and attached. Both DNS and traffic modules share the same ingress and egress hooks.");

    // Return unwrapped eBPF object so maps can be configured before wrapping in Arc
    Ok(ebpf)
}

