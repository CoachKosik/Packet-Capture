# Packet Capture - Using tcpdump to capture and analyze live network traffic from a Linux VM

## Objective

In this lab activity, you’ll perform tasks associated with using tcpdump to capture network traffic. You’ll capture the data in a packet capture (p-cap) file and then examine the contents of the captured packet data to focus on specific types of traffic.

## Project description

You’re a network analyst who needs to use tcpdump to capture and analyze live network traffic from a Linux virtual machine.

The lab starts with your user account, called analyst, already logged in to a Linux terminal.

Your Linux user's home directory contains a sample packet capture file that you will use at the end of the lab to answer a few questions about the network traffic that it contains.

Here’s how you’ll do this: 
  * First, you’ll identify network interfaces to capture network packet data.
  * Second, you’ll use tcpdump to filter live network traffic.
  * Third, you’ll capture network traffic using tcpdump.
  * Finally, you’ll filter the captured packet data.

## Skills Learned
1. Identifying Network Interfaces:
    * How to use the ifconfig command to list available network interfaces on a Linux system.
    * Recognizing the Ethernet interface identified by the eth prefix.
    * Using tcpdump -D to identify available interfaces (alternative to ifconfig).

2. Inspecting Network Traffic:
    * sing tcpdump -i <interface> -v -c <number> to capture and display detailed information about network packets on a specific interface.
Understanding the captured packet data, including:
    * Timestamp
    * Protocol (e.g., IP)
    * Source and destination IP addresses (or names) and ports
    * TCP flags (e.g., PUSH, ACK)
    * Sequence and acknowledgment numbers
    * Packet length

3. Capturing Network Traffic:
    * Using tcpdump -i <interface> -nn -c <number> port <port number> -w <filename> to capture a specific number of packets filtered by port number and save them to a file (pcap format).
    * The importance of the -nn option to avoid resolving IP addresses or ports to names for security reasons.
Using curl to generate traffic for a specific port (e.g., 80 for HTTP).

4. Filtering Captured Packet Data:
    * Using tcpdump -nn -r <filename> -v to view captured packet data from a pcap file with detailed information.
    * Using tcpdump -nn -r <filename> -X to view captured packet data in hexadecimal and ASCII format for advanced analysis.

This knowledge is valuable for security analysts who need to troubleshoot network issues, investigate suspicious activity, or analyze network performance.

## Tools Used
* **tcpdump:** This is a command-line network protocol analyzer tool used to capture and analyze packets traveling on a computer network interface.
* **ifconfig (or ip):** This is a command-line utility used to configure and view the network interfaces (e.g., eth0) on a Linux system. (The lab mentions ip as an alternative to ifconfig on some systems).
* **curl:** This is a command-line tool for transferring data to or from a server, often used to download content or simulate HTTP traffic.
* **ls:** This is a basic command-line utility used to list directory contents.

The activity primarily focuses on using tcpdump to capture network traffic, with additional usage of ifconfig (or ip) to identify available network interfaces and curl to generate sample traffic.

## Steps
### Task 1. Identify network interfaces
In this task, you must identify the network interfaces that can be used to capture network packet data.
**1. Identify the interfaces that are available:**
  * ![Packet Capture 1](https://github.com/user-attachments/assets/65e26e78-7ba9-41ac-aa47-54c7936d4c70)
    * The Ethernet network interface is identified by the entry with the eth prefix.
    * So, in this lab, you'll use eth0 as the interface that you will capture network packet data from in the following tasks.

**2. identify the interface options available for packet capture:**
  * ![Packet Capture 5](https://github.com/user-attachments/assets/1a666f25-8310-40b8-afc6-16fcc27f3c97)


### Task 2. Inspect the network traffic of a network interface with tcpdump
In this task, you must use tcpdump to filter live network packet traffic on an interface.

**1. Filter live network packet data from the eth0 interface:**
  * 'sudo tcpdump -i eth0 -v -c5'
    * ![Packet Capture 2](https://github.com/user-attachments/assets/b95d5c15-ed78-4531-9a2f-801413f05216)
  * This command will run tcpdump with the following options:
    * -i eth0: Capture data specifically from the eth0 interface.
    * -v: Display detailed packet data.
    * -c5: Capture 5 packets of data.

### Exploring network packet details
In this example, you’ll identify some of the properties that tcpdump outputs for the packet capture data you’ve just seen.

1. In the example data at the start of the packet output, tcpdump reported that it was listening on the eth0 interface, and it provided information on the link type and the capture size in bytes:
 
2. On the next line, the first field is the packet's timestamp, followed by the protocol type, IP:
 
3. The verbose option, -v, has provided more details about the IP packet fields, such as TOS, TTL, offset, flags, internal protocol type (in this case, TCP (6)), and the length of the outer IP packet in bytes:
  * ![Packet Capture 6](https://github.com/user-attachments/assets/f44389ed-2ed8-439f-a54d-f982ce7ffb2f)
    * *The specific details about these fields are beyond the scope of this lab. But you should know that these are properties that relate to the IP network packet.*

4. In the next section, the data shows the systems that are communicating with each other, and the remaining data filters the header data for the inner TCP packet: 
  * ![Packet Capture 7](https://github.com/user-attachments/assets/b0ee28ab-d6b5-4804-8a5c-bafd6c464434)
    * By default, tcpdump will convert IP addresses into names, as in the screenshot. The name of your Linux virtual machine, also included in the command prompt, appears here as the source for one packet and the destination for the second packet. In your live data, the name will be a different set of letters and numbers.
    * The direction of the arrow (>) indicates the direction of the traffic flow in this packet. Each system name includes a suffix with the port number (.5000 in the screenshot), which is used by the source and the destination systems for this packet.
    * The flags field identifies TCP flags. In this case, the P represents the push flag and the period indicates it's an ACK flag. This means the packet is pushing out data.
    * The next field is the TCP checksum value, which is used for detecting errors in the data.
    * This section also includes the sequence and acknowledgment numbers, the window size, and the length of the inner TCP packet in bytes.

### Task 3. Capture network traffic with tcpdump
In this task, you will use tcpdump to save the captured network data to a packet capture file.

In the previous command, you used tcpdump to stream all network traffic. Here, you will use a filter and other tcpdump configuration options to save a small sample that contains only web (TCP port 80) network packet data.

**1. Capture packet data into a file called capture.pcap:**
  * 'sudo tcpdump -i eth0 -nn -c9 port 80 -w capture.pcap &'
  * *You must press the ENTER key to get your command prompt back after running this command.*
  * This command will run tcpdump in the background with the following options:
    * -i eth0: Capture data from the eth0 interface.
    * -nn: Do not attempt to resolve IP addresses or ports to names.This is best practice from a security perspective, as the lookup data may not be valid. It also prevents malicious actors from being alerted to an investigation.
    * -c9: Capture 9 packets of data and then exit.
    * port 80: Filter only port 80 traffic. This is the default HTTP port.
    * -w capture.pcap: Save the captured data to the named file.
    * &: This is an instruction to the Bash shell to run the command in the background.
      * This command runs in the background, but some output text will appear in your terminal. The text will not affect the commands when you follow the steps for the rest of the lab.

**2. Use curl to generate some HTTP (port 80) traffic:**
  * 'curl opensource.google.com'
    * When the curl command is used like this to open a website, it generates some HTTP (TCP port 80) traffic that can be captured.

**3. Verify that packet data has been captured:**
  * 'ls -l capture.pcap'
    * ![Packet Capture 3](https://github.com/user-attachments/assets/8242cc85-9172-4d40-83f3-9efa20bd2161)

## Task 4. Filter the captured packet data
In this task, use tcpdump to filter data from the packet capture file you saved previously.

**1. Use the tcpdump command to filter the packet header data from the capture.pcap capture file.**
  * 'sudo tcpdump -nn -r capture.pcap -v'
  * ![Packet Capture 4](https://github.com/user-attachments/assets/a37d177a-9610-441c-a333-8c4b0a0e6f6b)
    * This command will run tcpdump with the following options:
      * -nn: Disable port and protocol name lookup.
      * -r: Read capture data from the named file.
      * -v: Display detailed packet data.
    * You must specify the -nn switch again here, as you want to make sure tcpdump does not perform name lookups of either IP addresses or ports, since this can alert threat actors.

**2. Use the tcpdump command to filter the extended packet data from the capture.pcap capture file:**
  * 'sudo tcpdump -nn -r capture.pcap -X'
  * ![Packet Capture 8](https://github.com/user-attachments/assets/178d5d88-c589-4916-bf7e-70a1adf0a8e5)
    * This command will run tcpdump with the following options:
      * -nn: Disable port and protocol name lookup.
      * -r: Read capture data from the named file.
      * -X: Display the hexadecimal and ASCII output format packet data.
    * Security analysts can analyze hexadecimal and ASCII output to detect patterns or anomalies during malware analysis or forensic analysis.

### Test your understanding

**1. What command would you use to capture 3 packets on any interface with the verbose option?**
  * Use the sudo tcpdump -c3 -i any -v.

**2. What does the -i option indicate?**
  * The -i option indicates the network interface to monitor.

**3. What type of information does the -v option include?**
  * The -v option provides verbose information.

**4. What tcpdump command can you use to identify the interfaces that are available to perform a packet capture on?**
  * Use the sudo tcpdump -D command.

### Summary
This lab demonstrated the process of capturing and analyzing network traffic using the `tcpdump` command-line tool. Key skills acquired include:

* Identifying network interfaces available for packet capture.
* Filtering network traffic based on specific criteria.
* Capturing network traffic and saving it to a file.
* Analyzing captured packet data to understand network protocols and data flow.

By mastering these techniques, users can gain valuable insights into network behavior and troubleshoot potential issues.
