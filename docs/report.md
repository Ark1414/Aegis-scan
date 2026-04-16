# AegisScan Project Report

Abstract
--------

AegisScan is an agent-less Windows system vulnerability and network scanner designed to identify misconfigurations, insecure services, missing patches, weak firewall rules and unsafe system parameters without installing any software on the target host. It leverages native Windows protocols such as SMB, RDP, WinRM and RPC to gather system posture and perform real-time security assessments.

---

## Chapter 1 — Introduction

### 1.1 Overview

Modern organizations rely heavily on Windows-based infrastructure for daily operations. With increasing cyber threats, misconfigurations, unpatched vulnerabilities and exposed network services pose significant risks. Traditional vulnerability scanners often require agents, causing deployment overhead and administrative challenges.

### 1.2 Project Objective & Scope

Objectives:
- Develop an agent-less vulnerability scanning system for Windows endpoints.
- Detect open network services, weak configurations and missing security patches.
- Design a centralized web platform to initiate, monitor and analyze scans.
- Build a secure backend API capable of returning real-time vulnerability results.
- Ensure scalability for enterprise-level multi-host scanning.

Scope:
- Host discovery
- Network port scanning
- Windows configuration assessment
- Vulnerability mapping
- JSON-based API output
- Web-based frontend for report visualization

### 1.3 Organization of Report

This report contains background, methodology, design, implementation, testing, results and future enhancements.

## Chapter 2 — Background and Literature Survey

### 2.1 Literature Survey

Existing tools like Nessus, OpenVAS and Qualys provide comprehensive scanning features but require heavy installations or paid subscriptions. Agent-less scanning using Windows’ native protocols offers lightweight and safe scanning without modifying the target system.

### 2.2 Requirement Specification

Functional Requirements:
- Host discovery
- Port and service scanning
- SMB/RDP/WinRM analysis
- Patch and configuration assessment
- API-based real-time results
- Web dashboard for visualization

Non-Functional Requirements:
- Performance, Security, Reliability, Scalability, Maintainability

### 2.3 Feasibility Report

Technical feasibility: Python, Flask, Impacket and Nmap-compatible logic make implementation feasible.

Operational feasibility: No agent installation required.

Economic feasibility: Open-source and cost-effective.

### 2.4 Innovativeness and Usefulness

Agent-less Windows scanning, real-time JSON APIs and a lightweight architecture give AegisScan advantages for SMBs and educational use.

### 2.5 Market Potential and Competitive Advantages

Lower deployment overhead and focused Windows posture checks provide a competitive position in markets that need lightweight scanning.

## Chapter 3 — Process Model

### 3.1 Proposed Methodology

An iterative, modular pipeline: Device Enumeration → System Audit → Port & Service Scan → Vulnerability Identification → Report Generation.

### 3.2 Software Process Model

Incremental Process Model to allow incremental delivery and testing of independent modules.

### 3.3 Project Plan

High-level schedule and deliverables (requirements, design, development, integration, testing, deployment).

### 3.4 Project Estimation & Scheduling

LOC estimate: ~1200–1500 lines. Development cadence: 8-week schedule with testing and integration phases.

## Chapter 4 — Design

### 4.1 Use Case Diagram

Actors: User (initiates scans, views results), System (executes scans, analyzes results, generates reports).

### 4.2 Sequence Diagram

User → ScannerController → SystemInfo → PortScanner → VulnerabilityEngine → ReportManager → Output

### 4.3 Activity Diagram

Initialization, enumeration, scanning, analysis, reporting.

### 4.4 Class Diagram

Key classes: ScannerController, SystemInfo, PortScanner, VulnerabilityEngine, ReportManager

### 4.5 E-R Diagram

Tables: DeviceInfo, ScanResults, Vulnerabilities

### 4.6 Data Flow Diagram

Level-0: User → AegisScan → Scan Output

### 4.7 Flow Chart

Start → Input Target → Gather System Info → Run Scanner → Analyze Results → Generate Report → End

### 4.8 Algorithm (Simplified)

1. Input target host
2. Fetch OS-level information
3. Scan ports using multi-threaded routine
4. Identify active services
5. Compare results with vulnerability database
6. Generate final report

## Chapter 5 — Technical Details

### 5.1 Software Specification

Language: Python
Frameworks/Libraries: socket, concurrent.futures, (optional) impacket, pywinrm
Database: JSON-based vulnerability definitions

### 5.2 Hardware Requirements

CPU: Intel i3 or above
RAM: 4GB minimum
Storage: 100MB free

## Chapter 6 — Implementation

Module descriptions:
- System Information Module: extracts OS/device data
- Network Scanner: TCP connect scans, multi-threaded
- Vulnerability Engine: signature matching
- Report Generator: JSON and web visualization

Integration done via ScannerController orchestrating modules.

## Chapter 7 — Testing & Results

### 7.1 Testing Methods Used

Unit tests for parsing and scan logic, integration testing for module interaction, functional testing against local hosts.

### 7.2 Test Cases & Results

Example test cases: valid IP scan, invalid IP error handling, vulnerability matching.

Observations: scanner is efficient on local networks and maintains acceptable scanning times.

## Chapter 8 — (omitted)

## Chapter 9 — Conclusion & Future Enhancements

Conclusion: AegisScan provides agent-less Windows posture and network scanning with a lightweight architecture suitable for educational and small enterprise use.

Future enhancements:
- Authenticated WinRM/WMI checks to enumerate patches and installed software (requires credentials handling)
- UDP scanning, service fingerprinting improvements, vulnerability signature updates
- Web UI with authentication and role-based access

## Chapter 10 — References

- Nessus, OpenVAS documentation
- Impacket project and Windows protocol references

---

Generated from user-provided project content. If you'd like a PDF or LaTeX version, I can add a `.tex` file and try to produce a PDF (requires a LaTeX toolchain or `pandoc` in the environment).
