Nmap & Scapy Assignment
1. Introduction
This assignment documents the reproduction of the Nmap and Scapy practical labs covered during class. The goal was to rerun all demonstrations, understand how each tool functions, and summarize the learning outcomes, challenges, and relevance of these tools in real world cybersecurity operations.
2. Nmap Lab Activities
2.1 Host Discovery
Commands practiced:
•	nmap -sn <target>
 
Purpose: Identify live hosts on a network without scanning ports.
Observation: ARP and ICMP ping sweeps are efficient for mapping active devices.
2.3 Service Version Detection
Command:
•	nmap -sV <target>
 
Purpose: Identify versions of running services.
Observation: Helps assess vulnerabilities linked to outdated software.
2.4 OS Fingerprinting
Command:
•	nmap -O <target>
 
Purpose: Detect operating system based on TCP/IP behavior.
Observation: Useful for attacker profiling and target defense strategies.
2.5 Aggressive Scan
Command:
•	nmap -A <target>

Purpose: Combine OS detection, service detection, scripts, and traceroute.
Observation: Powerful but noisy should be used carefully in real environments.
2.6 Basic Nmap Scripting Engine (NSE) Usage
3. Scapy Lab Activities
3.1 Packet Crafting
Example:
packet = IP(dst="192.168.1.10")/TCP(dport=80, flags="S")
send(packet)
Purpose: Create custom packets for testing firewalls or protocols.
3.2 Packet Sending
•	Used send(), sr(), sr1()
Observation: Allows low-level control over packet transmission.
3.3 Packet Sniffing
Example:
sniff(filter="tcp", count=10)
 
Purpose: Capture and analyze live network traffic.
Observation: Required elevated permissions; useful for debugging and intrusion analysis.
4. Summary & Reflection
4.1 What I Learned
•	How to enumerate hosts, services, and operating systems using Nmap.
•	How to craft, send, and sniff packets using Scapy.
•	How to analyze network traffic and interpret protocol behaviors.
•	How Nmap and Scapy complement each other one for scanning, one for packet-level control.
4.2 What Was Challenging
•	Running Scapy sniffing required root/administrator privileges.
•	Understanding some advanced Nmap flags and NSE scripts.
•	Crafting packets correctly without breaking protocol structure.
•	Interpreting raw packet output during Scapy analysis.
4.3 Real World Cybersecurity Importance
•	Nmap is essential for penetration testing, vulnerability assessment, network auditing, and asset discovery.
•	Scapy is crucial for incident response, protocol testing, exploit development, and understanding how attacks like spoofing or scanning work at the packet level.
•	Both tools help cybersecurity professionals detect weaknesses, verify defenses, and understand attacker behavior.
5. Conclusion
Reproducing the Nmap and Scapy labs strengthened my technical skills in network scanning, reconnaissance, packet crafting, and analysis. These tools play a critical role in modern cybersecurity practices, and the hands-on experience provided deeper insight into both offensive and defensive security operations.
