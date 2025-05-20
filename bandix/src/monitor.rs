use std::fmt::Display;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum TrafficDirection {
    Ingress,
    Egress,
}

impl Display for TrafficDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrafficDirection::Ingress => write!(f, "Ingress"),
            TrafficDirection::Egress => write!(f, "Egress"),
        }
    }
}

#[derive(Debug)]
pub struct Monitor {
    pub interface: String,
    pub traffic_direction: TrafficDirection,
}

impl Display for Monitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "interface: {}, traffic_direction: {}",
            self.interface, self.traffic_direction
        )
    }
}
