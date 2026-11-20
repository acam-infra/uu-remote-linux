//! Cross-platform ICE interface, IP-range, and remote host-candidate filtering.
//! Prevents WebRTC from nesting inside overlay virtual networks (Tailscale, ZeroTier,
//! WireGuard, Clash/Sing-box TUN) across Linux, macOS, and Windows.

use std::net::IpAddr;
use webrtc::api::setting_engine::SettingEngine;

/// Virtual/overlay interface name prefixes across Linux, macOS, and Windows.
const BLOCKED_INTERFACE_PREFIXES: &[&str] = &[
    "tailscale",
    "wg",
    "tun",
    "tap",
    "utun",
    "zt",
    "zerotier",
    "meta",
    "mihomo",
    "sing",
    "flannel",
    "cali",
    "cni",
    "docker",
    "br-",
    "veth",
    "virbr",
    "vmnet",
    "vboxnet",
    "lo",
];

/// Returns true if the operator explicitly opted into allowing overlay ICE candidates
/// via `UU_ALLOW_OVERLAY_ICE=1` or `UU_ALLOW_OVERLAY_ICE=true`.
pub fn overlay_ice_allowed_by_env() -> bool {
    std::env::var("UU_ALLOW_OVERLAY_ICE")
        .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

/// Returns true if the operator requested immediate TURN relay mode via
/// `UU_FORCE_RELAY=1` or `UU_FORCE_RELAY=true` (skips 2.5s futile STUN hole-punching
/// on dual-Symmetric-NAT links).
pub fn force_relay_by_env() -> bool {
    std::env::var("UU_FORCE_RELAY")
        .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

/// Pure check for interface name against known virtual/overlay adapter prefixes.
pub fn is_physical_interface_name(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }
    !BLOCKED_INTERFACE_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

/// Runtime interface filter honoring `UU_ALLOW_OVERLAY_ICE=1`.
pub fn interface_allowed(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    if lower == "lo" || lower.starts_with("lo") {
        return false;
    }
    if overlay_ice_allowed_by_env() {
        return true;
    }
    is_physical_interface_name(name)
}

/// Returns true if `ip` belongs to an overlay VPN or proxy TUN virtual subnet:
/// - `100.64.0.0/10` (RFC 6598 CGNAT used by Tailscale / Headscale across all OSes)
/// - `198.18.0.0/15` (RFC 2544 benchmark range used by Clash / Mihomo / Sing-box Fake-IP TUN)
/// - `fd7a:115c:a1e0::/48` (Tailscale IPv6 ULA prefix across all OSes)
/// - Loopback or link-local addresses
pub fn is_overlay_or_virtual_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() {
                return true;
            }
            let o = v4.octets();
            // 100.64.0.0/10 -> first octet 100, top two bits of second octet 0b01 (64..=127)
            let is_tailscale_cgnat = o[0] == 100 && (o[1] & 0b1100_0000) == 64;
            // 198.18.0.0/15 -> first octet 198, second octet 18 or 19
            let is_proxy_fakeip = o[0] == 198 && (o[1] & 0xfe) == 18;
            is_tailscale_cgnat || is_proxy_fakeip
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return true;
            }
            let s = v6.segments();
            // Tailscale IPv6 ULA: fd7a:115c:a1e0::/48
            let is_tailscale_ula = s[0] == 0xfd7a && s[1] == 0x115c && s[2] == 0xa1e0;
            // Link-local fe80::/10
            let is_link_local = (s[0] & 0xffc0) == 0xfe80;
            is_tailscale_ula || is_link_local
        }
    }
}

/// Runtime local IP filter for `SettingEngine::set_ip_filter`.
pub fn ip_allowed(ip: IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return false;
    }
    if overlay_ice_allowed_by_env() {
        return true;
    }
    !is_overlay_or_virtual_ip(ip)
}

/// Filters remote ICE candidates received via signaling (`soac`) before injection.
/// Even if the remote peer is an unmodified official Windows/macOS client that advertises
/// its local Tailscale IP (`100.64.0.0/10` or `fd7a:115c:a1e0::/48`) as a `typ host` candidate,
/// dropping that `typ host` candidate prevents forming an overlay-in-overlay tunnel while
/// keeping `srflx`, `prflx`, and `relay` candidates intact.
pub fn remote_candidate_allowed(sdp_candidate: &str) -> bool {
    if overlay_ice_allowed_by_env() {
        return true;
    }
    is_remote_candidate_permitted(sdp_candidate)
}

/// Pure check on an SDP candidate line (`candidate:...` or `a=candidate:...`).
pub fn is_remote_candidate_permitted(sdp_candidate: &str) -> bool {
    let line = sdp_candidate.trim();
    let line = line.strip_prefix("a=").unwrap_or(line);
    let fields: Vec<&str> = line.split_whitespace().collect();
    // Standard RFC 8839 format:
    // 0: candidate:<foundation> 1: <component> 2: <transport> 3: <priority> 4: <ip> 5: <port> 6: typ 7: <type>
    if fields.len() >= 8 && fields[6].eq_ignore_ascii_case("typ") && fields[7].eq_ignore_ascii_case("host") {
        if let Ok(ip) = fields[4].parse::<IpAddr>() {
            if is_overlay_or_virtual_ip(ip) {
                return false;
            }
        }
    }
    true
}

/// Applies cross-platform anti-overlay interface and IP filters to a `webrtc-rs` `SettingEngine`.
pub fn apply_setting_engine(se: &mut SettingEngine) {
    se.set_ice_multicast_dns_mode(webrtc::ice::mdns::MulticastDnsMode::Disabled);
    se.set_interface_filter(Box::new(|name: &str| interface_allowed(name)));
    se.set_ip_filter(Box::new(|ip: IpAddr| ip_allowed(ip)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_tailscale_wireguard_tun_and_container_interfaces() {
        for blocked in [
            "tailscale0",
            "Tailscale",
            "wg0",
            "tun0",
            "tap0",
            "utun3",
            "ztfp6jdvog",
            "ZeroTier",
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
        for allowed in ["eth0", "eno1", "enp5s0", "wlp3s0", "ens5", "host0", "wlan0"] {
            assert!(is_physical_interface_name(allowed), "should allow {allowed}");
        }
    }

    #[test]
    fn blocks_tailscale_cgnat_ipv4_ula_ipv6_and_clash_fakeip() {
        for blocked_ip in [
            "100.64.0.1",
            "100.79.113.126",
            "100.80.42.7",
            "100.127.255.254",
            "198.18.0.1",
            "198.19.255.254",
            "127.0.0.1",
            "169.254.1.1",
            "fd7a:115c:a1e0::e935:2a0b",
            "fd7a:115c:a1e0:ab12:4843:cd96:6258:b240",
            "::1",
            "fe80::1",
        ] {
            let ip: IpAddr = blocked_ip.parse().unwrap();
            assert!(is_overlay_or_virtual_ip(ip), "should block overlay IP {blocked_ip}");
        }

        for allowed_ip in [
            "10.128.4.143",
            "10.203.82.2",
            "172.16.0.10",
            "192.168.1.50",
            "100.63.255.254",
            "100.128.0.1",
            "198.17.255.254",
            "198.20.0.1",
            "119.28.84.98",
            "43.167.10.95",
            "240e:390:1234::1",
        ] {
            let ip: IpAddr = allowed_ip.parse().unwrap();
            assert!(!is_overlay_or_virtual_ip(ip), "should allow non-overlay IP {allowed_ip}");
        }
    }

    #[test]
    fn filters_remote_overlay_host_candidates_but_preserves_srflx_and_relay() {
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
    }
}
