# Modbus MITM Hijack Attack
1. Spoof ARP
2. Intercept Modbus Packet
3. Change Values
4. ???
5. Profit

Requires: scapy, root privileges, and IPv4 forwarding support
  pip install scapy --break-system-packages

## Usage
`sudo python3 modbus_mitm_capture.py -i eth0 --victim 192.168.1.50 --target 192.168.1.10`

  
## Features to add
 - interactive mode: open prompt when the first modbus packet hits us, and allow user to select exactly what function and value they want to send
 - more output/logging to help debug + improve user experience
 - a nice banner, ofc
 - rename 'victim' and 'target' to 'client' and 'server'
 - add short flags
 - complete other TODOs