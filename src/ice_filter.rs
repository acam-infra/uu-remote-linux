//! Cross-platform 4-layer ICE interface, IP-range, trickle-candidate, and SDP candidate filtering.
//! Prevents WebRTC from nesting inside overlay virtual networks (Tailscale, Headscale, ZeroTier,
//! WireGuard, Clash/Mihomo/Sing-box TUN, WSL/Hyper-V/Docker bridges) across Linux, macOS, and Windows.

use std::net::IpAddr;
use webrtc::api::setting_engine::SettingEngine;

/// Short virtual/overlay interface name prefixes across Linux, macOS, and BSD.
const BLOCKED_INTERFACE_PREFIXES: &[&str] = &[
    "tailscale",
    "ts",
    "wg",
    "tun",
    "tap",
    "utun",
    "zt",
    "zerotier",
    "meta",
    "mihomo",
    "sing",
    "clash",
    "flannel",
    "cali",
    "cni",
    "docker",
    "br-",
    "bridge",
    "veth",
    "virbr",
    "vmnet",
    "vboxnet",
    "awdl",
    "llw",
    "anpi",
    "anri",
    "gif",
    "stf",
    "lo",
];

/// Substring keywords matched against full adapter names (critical on Windows where
/// `if-addrs` returns Friendly Names such as `"Local Area Connection (Tailscale)"`,
/// `"WireGuard Tunnel"`, `"Wintun Userspace Tunnel"`, `"TAP-Windows Adapter V9"`,
/// `"vEthernet (WSL)"`, or `"Sing-Box Tunnel"`).
const BLOCKED_INTERFACE_SUBSTRINGS: &[&str] = &[
    "tailscale",
    "wireguard",
    "wintun",
    "zerotier",
    "mihomo",
    "clash",
    "sing-box",
    "singbox",
    "tap-windows",
    "vethernet",
    "hyper-v",
    "wsl",
    "loopback",
];

pub fn overlay_ice_allowed_by_env() -> bool {
    std::env::var("UU_ALLOW_OVERLAY_ICE")
        .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

pub fn force_relay_by_env() -> bool {
    std::env::var("UU_FORCE_RELAY")
        .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

pub fn is_physical_interface_name(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }
    if BLOCKED_INTERFACE_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
    {
        return false;
    }
    if BLOCKED_INTERFACE_SUBSTRINGS
        .iter()
        .any(|kw| lower.contains(kw))
    {
        return false;
    }
    true
}

pub fn interface_allowed(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    if lower == "lo" || lower.starts_with("lo0") || lower.contains("loopback") {
        return false;
    }
    if overlay_ice_allowed_by_env() {
        return true;
    }
    is_physical_interface_name(name)
}

pub fn is_overlay_or_virtual_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() {
                return true;
            }
            let o = v4.octets();
            let is_tailscale_cgnat = o[0] == 100 && (o[1] & 0b1100_0000) == 64;
            let is_proxy_fakeip = o[0] == 198 && (o[1] & 0xfe) == 18;
            is_tailscale_cgnat || is_proxy_fakeip
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return true;
            }
            if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                return is_overlay_or_virtual_ip(IpAddr::V4(mapped_v4));
            }
            let s = v6.segments();
            let is_ula = (s[0] & 0xfe00) == 0xfc00;
            let is_link_local = (s[0] & 0xffc0) == 0xfe80;
            is_ula || is_link_local
        }
    }
}

pub fn ip_allowed(ip: IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return false;
    }
    if overlay_ice_allowed_by_env() {
        return true;
    }
    !is_overlay_or_virtual_ip(ip)
}

pub fn remote_candidate_allowed(sdp_candidate: &str) -> bool {
    if overlay_ice_allowed_by_env() {
        return true;
    }
    is_remote_candidate_permitted(sdp_candidate)
}

pub fn is_remote_candidate_permitted(sdp_candidate: &str) -> bool {
    let line = sdp_candidate.trim();
    let line = line.strip_prefix("a=").unwrap_or(line);
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() >= 8 && fields[6].eq_ignore_ascii_case("typ") && fields[7].eq_ignore_ascii_case("host") {
        if let Ok(ip) = fields[4].parse::<IpAddr>() {
            if is_overlay_or_virtual_ip(ip) {
                return false;
            }
        }
    }
    true
}

pub fn sanitize_remote_sdp(sdp: &str) -> String {
    if overlay_ice_allowed_by_env() {
        return sdp.to_owned();
    }
    strip_overlay_candidates_from_sdp(sdp)
}

pub fn strip_overlay_candidates_from_sdp(sdp: &str) -> String {
    let mut out = String::with_capacity(sdp.len());
    for line in sdp.split_inclusive('\n') {
        let trimmed = line.trim();
        if (trimmed.starts_with("a=candidate:") || trimmed.starts_with("candidate:"))
            && !is_remote_candidate_permitted(trimmed)
        {
            continue;
        }
        out.push_str(line);
    }
    out
}

pub fn apply_setting_engine(se: &mut SettingEngine) {
    se.set_ice_multicast_dns_mode(webrtc::ice::mdns::MulticastDnsMode::Disabled);
    se.set_interface_filter(Box::new(|name: &str| interface_allowed(name)));
    se.set_ip_filter(Box::new(|ip: IpAddr| ip_allowed(ip)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_tailscale_wireguard_tun_windows_macos_and_container_interfaces() {
        for blocked in [
            "tailscale0",
            "Tailscale",
            "Local Area Connection (Tailscale)",
            "WireGuard Tunnel - office",
            "Wintun Userspace Tunnel",
            "TAP-Windows Adapter V9",
            "vEthernet (WSL (Hyper-V firewall))",
            "Sing-Box Tunnel",
            "Clash Meta TUN",
            "wg0",
            "tun0",
            "tap0",
            "utun4",
            "awdl0",
            "llw0",
            "anpi0",
            "ztfp6jdvog",
            "ZeroTier One [1a2b3c]",
            "Meta",
            "mihomo0",
            "docker0",
            "br-1a2b3c",
            "veth12",
            "virbr0",
            "lo",
        ] {
            assert!(!is_physical_interface_name(blocked), "should block {blocked}");
        }
        for allowed in ["eth0", "eno1", "enp5s0", "wlp3s0", "ens5", "en0", "wlan0", "Ethernet 2", "Wi-Fi"] {
            assert!(is_physical_interface_name(allowed), "should allow {allowed}");
        }
    }

    #[test]
    fn blocks_tailscale_cgnat_ipv4_ula_ipv6_mapped_v6_and_clash_fakeip() {
        for blocked_ip in [
            "100.64.0.1",
            "100.79.113.126",
            "100.99.0.4",
            "100.99.3.10",
            "100.127.255.254",
            "198.18.0.1",
            "198.19.255.254",
            "127.0.0.1",
            "169.254.176.240",
            "fd7a:115c:a1e0::ae35:363a",
            "fd7a:115c:a1e0::2c34:fa59",
            "fd00:dead:beef::1",
            "fc00::1234",
            "::ffff:100.79.113.126",
            "::ffff:198.18.0.2",
            "::1",
            "fe80::1",
        ] {
            let ip: IpAddr = blocked_ip.parse().unwrap();
            assert!(is_overlay_or_virtual_ip(ip), "should block overlay IP {blocked_ip}");
        }

        for allowed_ip in [
            "10.128.4.143",
            "10.153.35.30",
            "7.249.204.24",
            "172.16.0.10",
            "192.168.1.50",
            "100.63.255.254",
            "100.128.0.1",
            "198.17.255.254",
            "198.20.0.1",
            "119.28.84.98",
            "240e:390:1234::1",
        ] {
            let ip: IpAddr = allowed_ip.parse().unwrap();
            assert!(!is_overlay_or_virtual_ip(ip), "should allow non-overlay IP {allowed_ip}");
        }
    }

    #[test]
    fn filters_remote_overlay_host_candidates_and_sanitizes_sdp() {
        let ts_host_v4 = "candidate:1 1 UDP 2130706431 100.79.113.126 54742 typ host";
        let ts_host_v6 = "a=candidate:2 1 UDP 2130706431 fd7a:115c:a1e0::d935:7181 54014 typ host";
        let clash_host = "candidate:3 1 UDP 2130706431 198.18.0.2 50000 typ host";
        let lan_host = "candidate:4 1 UDP 2130706431 10.128.4.143 54606 typ host";
        let srflx_cgnat = "candidate:5 1 UDP 1694498815 100.80.42.7 60123 typ srflx raddr 10.0.0.2 rport 50000";
        let turn_relay = "candidate:6 1 UDP 16777215 119.28.71.87 34780 typ relay raddr 0.0.0.0 rport 0";

        assert!(!is_remote_candidate_permitted(ts_host_v4));
        assert!(!is_remote_candidate_permitted(ts_host_v6));
        assert!(!is_remote_candidate_permitted(clash_host));
        assert!(is_remote_candidate_permitted(lan_host));
        assert!(is_remote_candidate_permitted(srflx_cgnat));
        assert!(is_remote_candidate_permitted(turn_relay));

        let raw_sdp = format!(
            "v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na={ts_host_v4}\r\n{ts_host_v6}\r\na={lan_host}\r\na={turn_relay}\r\n"
        );
        let cleaned = strip_overlay_candidates_from_sdp(&raw_sdp);
        assert!(!cleaned.contains("100.79.113.126"));
        assert!(!cleaned.contains("fd7a:115c:a1e0"));
        assert!(cleaned.contains("10.128.4.143"));
        assert!(cleaned.contains("119.28.71.87"));
    }
}
