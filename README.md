# Modbus Packet Injection (MoPI) 
Modbus MITM/AiTM Packet Injection Attack
1. Spoof ARP
2. Intercept Modbus Packet
3. Change Values
4. ???
5. Profit

Requires: scapy, root privileges

`pip install scapy --break-system-packages`

## Usage
MoPI has 3 modes: packet injection, packet sniffig, and flip

### Passive Sniffing
Passive Sniffing is the default mode. The program will ARP poisin the targets and sniff for Modbus traffic going across the wire, presenting this back to the user.

`sudo python3 mopi.py -i eth0 --victim 192.168.1.50 --target 192.168.1.10 --mode passive`

### Packet Injection
Packet Injection mode allows the user to craft a Modbus packet of their own, which will be inject into the TCP session next time traffic is seen.

`sudo python3 mopi.py -i eth0 --victim 192.168.1.50 --target 192.168.1.10 --mode injetion`

The user will be prompted to craft their packet via an interactive process.

### Flip
TODO
`sudo python3 mopi.py -i eth0 --victim 192.168.1.50 --target 192.168.1.10 --mode flip`


  
## TODO
- more output/logging to help debug + improve user experience
- rename 'victim' and 'target' to 'client' and 'server'
- complete other TODOs
- add more try/except logic, especially for interactive packet creation
- add more modes like:
  - random
  - config file

Current issue with modifying packets is as follows:
The packet is sent from the client, to us, then modified, then sent to the server. The response receieved from the server is of course a response to the modified request. We can't just send that back to the client. We need a way of crafting a fake response.