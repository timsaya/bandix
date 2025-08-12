use super::remove_rlimit_memlock;
use super::EbpfTrafficDirection;
use aya::programs::{tc, SchedClassifier, TcAttachType};

pub async fn load_ingress(iface: String) -> anyhow::Result<aya::Ebpf> {
    remove_rlimit_memlock();

    let traffic_direction = EbpfTrafficDirection::Ingress as i32;

    let mut ebpf = aya::EbpfLoader::new()
        .set_global("TRAFFIC_DIRECTION", &traffic_direction, true)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/bandix"
        )))
        .unwrap();


    let _ = tc::qdisc_add_clsact(&iface);
    let program: &mut SchedClassifier = ebpf.program_mut("bandix").unwrap().try_into().unwrap();

    program.load().unwrap();
    program.attach(&iface, TcAttachType::Ingress).unwrap();

    Ok(ebpf)
}
