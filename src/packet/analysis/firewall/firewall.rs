use super::{Filter, FirewallPacket, Policy};
use std::collections::HashMap;

#[derive(Debug)]
pub struct IpFirewall {
    rules: HashMap<Filter, u8>,
    policy: Policy,
}

impl IpFirewall {
    pub fn new(policy: Policy) -> Self {
        Self { rules: HashMap::new(), policy }
    }

    pub fn add_rule(&mut self, filter: Filter, priority: u8) {
        self.rules.insert(filter, priority);
    }

    pub fn check(&self, packet: &FirewallPacket) -> bool {
        let mut block = false;
        let mut allow = false;
        let mut max_priority = 0;

        for (filter, priority) in &self.rules {
            if *priority > max_priority {
                let matches = match filter {
                    // L2 Filters
                    Filter::SrcMacAddress(mac) => &packet.src_mac == mac,
                    Filter::DstMacAddress(mac) => &packet.dst_mac == mac,
                    Filter::EtherType(ether_type) => packet.ether_type.value() == *ether_type,

                    // L3 Filters
                    Filter::SrcIpAddress(ip) => &packet.src_ip == ip,
                    Filter::DstIpAddress(ip) => &packet.dst_ip == ip,
                    Filter::IpProtocol(protocol) => packet.ip_protocol.value() == *protocol,

                    // L4 Filters
                    Filter::SrcPort(port) => packet.src_port == *port,
                    Filter::DstPort(port) => packet.dst_port == *port,
                };

                if matches {
                    max_priority = *priority;
                    match self.policy {
                        Policy::Whitelist => allow = true,
                        Policy::Blacklist => block = true,
                    }
                }
            }
        }

        match self.policy {
            Policy::Whitelist => allow,
            Policy::Blacklist => !block,
        }
    }
}
