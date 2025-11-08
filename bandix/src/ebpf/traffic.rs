use super::remove_rlimit_memlock;
use aya::programs::{tc, SchedClassifier, TcAttachType};

/// Load traffic eBPF programs (ingress and egress)
pub async fn load_traffic(iface: String) -> anyhow::Result<(aya::Ebpf, aya::Ebpf)> {
    remove_rlimit_memlock();

    // Load ingress eBPF program
    let mut ingress_ebpf = aya::EbpfLoader::new()
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/bandix"
        )))
        .unwrap();

    let _ = tc::qdisc_add_clsact(&iface);
    let ingress_program: &mut SchedClassifier = ingress_ebpf
        .program_mut("traffic_ingress")
        .unwrap()
        .try_into()
        .unwrap();

    ingress_program.load().unwrap();
    ingress_program.attach(&iface, TcAttachType::Ingress).unwrap();

    // Load egress eBPF program
    let mut egress_ebpf = aya::EbpfLoader::new()
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/bandix"
        )))
        .unwrap();

    let egress_program: &mut SchedClassifier = egress_ebpf
        .program_mut("traffic_egress")
        .unwrap()
        .try_into()
        .unwrap();

    egress_program.load().unwrap();
    egress_program.attach(&iface, TcAttachType::Egress).unwrap();

    Ok((ingress_ebpf, egress_ebpf))
}

