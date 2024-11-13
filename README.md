# Intrusion Detection System (IDS) using Snort

Welcome to the **Intrusion Detection System (IDS)** powered by Snort! This project leverages custom Snort rules to detect various forms of network reconnaissance, attacks, and suspicious activities, providing a robust layer of security against potential threats. The project includes 30+ custom rules that are meticulously designed to recognize and respond to malicious network behavior.

## Table of Contents
- [Project Overview](#project-overview)
- [Key Features](#key-features)
- [Snort Rules Overview](#snort-rules-overview)
- [Setup and Usage](#setup-and-usage)

## Project Overview
This IDS project is tailored to detect multiple cyber attack vectors, reconnaissance attempts, and unauthorized access attempts. By using Snort, an open-source network intrusion prevention system (NIPS) and network intrusion detection system (NIDS), this system actively monitors network traffic for suspicious behavior and alerts the security team of potential threats.

## Contributors

- **Anmol**
- **Chaman Rathore** 
- **Daksh**

## Key Features
- **Reconnaissance Detection**: Identifies port scanning, ping sweeps, and protocol fingerprinting.
- **Injection Attack Detection**: SQL Injection (SQLi), Cross-Site Scripting (XSS), and Local File Inclusion (LFI) detection.
- **Brute Force Attack Detection**: SSH, FTP, and HTTP brute-force detection.
- **Vulnerability Exploitation Detection**: Monitors attempts to exploit web vulnerabilities such as RFI, LFI, RCE, and SSRF.
- **Evasion and Bypass Tactics**: Detects stealthy scans like NULL, FIN, Xmas tree, and window scans.
- **Access Violation Alerts**: Triggers alerts on attempts to access restricted files or directories.

## Snort Rules Overview

Here’s an overview of the Snort rules included, with code examples where applicable:



These are some Screenshots of Some Examples:

NULL SCAN
![WhatsApp Image 2024-11-13 at 11 59 58 PM(2)](https://github.com/user-attachments/assets/2edb8f13-2b04-43ec-a5df-be265bca6468)

ACK SCAN
![WhatsApp Image 2024-11-13 at 11 59 58 PM(1)](https://github.com/user-attachments/assets/96a4d6f9-43f5-48aa-bd18-801deca2b0c4)

SYN ACK SCAN
![WhatsApp Image 2024-11-13 at 11 59 58 PM](https://github.com/user-attachments/assets/03ba022f-0d7f-4e4b-a3d4-0514aec7c8ec)





### 1. **Reconnaissance**
   - **HTTP OPTIONS Scan**: Detects HTTP OPTIONS method scans, commonly used in reconnaissance.
     ```snort
     alert tcp any any -> any 80 (msg:"Reconnaissance: HTTP OPTIONS method scan"; flow:to_server,established; content:"OPTIONS"; http_method; sid:100001;)
     ```
   - **Ping Sweep**: Monitors ICMP Echo Requests to identify ping sweeps.
     ```snort
     alert icmp any any -> any any (msg:"Reconnaissance: Ping sweep detected"; itype:8; sid:100005;)
     ```

### 2. **Injection Attacks**
   - **SQL Injection**: Detects SQL keywords in HTTP requests indicative of SQL injection attempts.
     ```snort
     alert tcp any any -> any 80 (msg:"SQL Injection attempt"; flow:to_server,established; content:"select"; http_uri; sid:100002;)
     ```
   - **Cross-Site Scripting (XSS)**: Detects `<script>` tags in HTTP requests, a common vector for XSS attacks.
     ```snort
     alert tcp any any -> any 80 (msg:"Cross-Site Scripting (XSS) attempt"; flow:to_server,established; content:"<script>"; nocase; sid:100019;)
     ```
   - **Remote Code Execution (RCE)**: Detects command execution attempts remotely.
     ```snort
     alert tcp any any -> any 80 (msg:"Remote Code Execution attempt"; flow:to_server,established; content:"/bin/bash"; sid:100017;)
     ```

### 3. **Brute Force Attacks**
   - **SSH Brute Force**: Detects multiple SSH login attempts in a short period.
     ```snort
     alert tcp any any -> any 22 (msg:"SSH Brute Force attempt"; flags:S; threshold:type both, track by_src, count 5, seconds 60; sid:100006;)
     ```
   - **FTP Brute Force**: Detects repeated login attempts on FTP.
     ```snort
     alert tcp any any -> any 21 (msg:"FTP Brute Force attempt"; flags:S; threshold:type both, track by_src, count 5, seconds 60; sid:100010;)
     ```
   - **HTTP Brute Force Login**: Detects repeated login attempts on HTTP endpoints.
     ```snort
     alert tcp any any -> any 80 (msg:"HTTP Brute Force Login attempt"; flow:to_server,established; content:"POST"; http_method; threshold:type both, track by_src, count 5, seconds 60; sid:100014;)
     ```

### 4. **Vulnerability Exploitation**
   - **Local File Inclusion (LFI)**: Detects access attempts to sensitive files.
     ```snort
     alert tcp any any -> any 80 (msg:"Local File Inclusion (LFI) attempt"; flow:to_server,established; content:"/etc/passwd"; http_uri; sid:100015;)
     ```
   - **Remote File Inclusion (RFI)**: Detects attempts to include remote files.
     ```snort
     alert tcp any any -> any 80 (msg:"Remote File Inclusion (RFI) attempt"; flow:to_server,established; content:"http://"; http_uri; sid:100016;)
     ```
   - **Server-Side Request Forgery (SSRF)**: Detects SSRF attempts targeting internal resources.
     ```snort
     alert tcp any any -> any 80 (msg:"SSRF attempt"; flow:to_server,established; content:"127.0.0.1"; http_header; sid:100021;)
     ```

### 5. **Evasion Techniques**
   - **NULL Scan**: Detects TCP packets with no flags set, indicating a NULL scan.
     ```snort
     alert tcp any any -> any any (msg:"Potential NULL scan"; flags:0; sid:100036;)
     ```
   - **Xmas Tree Scan**: Detects packets with FIN, PSH, and URG flags set.
     ```snort
     alert tcp any any -> any any (msg:"Potential Xmas Tree scan"; flags: FPU; sid:100039;)
     ```
   - **SYN Scan**: Monitors abnormal SYN patterns, indicating SYN scan activity.

     ```snort
     alert tcp any any -> any any (msg:"Potential SYN scan"; flags:S; threshold:type both, track by_src, count 5, seconds 60; sid:100040;)
     ```

### 6. **File and Directory Access**
   - **Sensitive File Access**: Detects attempts to access sensitive or backup files.
     ```snort
     alert tcp any any -> any 80 (msg:"Sensitive File Access Attempt"; flow:to_server,established; content:"backup"; http_uri; sid:100029;)
     ```
   - **Directory Traversal**: Identifies attempts to access files via directory traversal techniques.
     ```snort
     alert tcp any any -> any 80 (msg:"Directory Traversal Attempt"; flow:to_server,established; content:"../"; http_uri; sid:100033;)
     ```

### 7. **Miscellaneous**
   - **DNS Queries to Malicious Domains**: Detects DNS requests to known malicious domains.
     ```snort
     alert udp any any -> any 53 (msg:"DNS Query to Malicious Domain"; content:"malicious.com"; nocase; sid:100026;)
     ```
   - **Suspicious ICMP Packet Size**: Flags ICMP packets exceeding normal size.
     ```snort
     alert icmp any any -> any any (msg:"Suspicious ICMP packet size"; dsize:>1400; sid:100025;)
     ```

## Setup and Usage

To deploy and run this IDS with the custom Snort rules:

1. **Install Snort**: Ensure that Snort is installed on your system. [Installation Guide](https://www.snort.org/downloads)
2. **Configure Snort Rules**: Copy the provided rules into your Snort rules directory (usually located at `/etc/snort/rules/`).
3. **Run Snort**: Start Snort in network intrusion detection mode:
   ```bash
   snort -c /etc/snort/snort.conf -l /var/log/snort
