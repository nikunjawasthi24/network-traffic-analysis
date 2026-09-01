# Network Traffic Analysis Using Wireshark and Zeek

## Project Overview

This project demonstrates network traffic analysis in a simulated client-server environment using Wireshark and Zeek.

## Objectives

- Create a simulated client-server network
- Generate network traffic
- Capture packets using tcpdump
- Analyze packets using Wireshark
- Analyze traffic using Zeek
- Automate traffic analysis using Python
- Identify unusual network connections

## Technologies Used

- Kali Linux
- Linux Network Namespaces
- Wireshark
- Zeek
- tcpdump
- Python
- Podman

## Architecture

Client (10.10.0.2)
        |
        | Network Traffic
        |
Server (10.10.0.3)
        |
     tcpdump
        |
traffic_final.pcap
        |
   +----+----+
   |         |
Wireshark   Zeek
              |
          conn.log
              |
       Python Analyzer
              |
      Normal / Suspicious

## Results

The final experiment analyzed 3 connections:

- Normal connections: 2
- Suspicious connections: 1

The suspicious connection was associated with destination port 4444.

## Project Structure

- `scripts/` - Python analysis script
- `reports/` - Generated analysis report
- `zeek-logs/` - Zeek-generated logs
- `captures/` - Network packet capture

## Conclusion

The project successfully demonstrates a basic network monitoring and security-analysis workflow using a simulated network, Wireshark, Zeek, and Python.
