# SOC Analyst Home Lab

A practical cloud-based Security Operations Center (SOC) home lab designed for learning security monitoring, log analysis, threat detection, incident response, and SIEM operations.

## Project Goals

- Build a practical SOC environment in the cloud
- Learn Splunk SIEM administration and log analysis
- Collect and analyze endpoint security logs
- Develop SOC detection and investigation skills
- Practice incident response workflows
- Document the entire learning journey as a cybersecurity portfolio

## Lab Environment

### Cloud Infrastructure

- Cloud Provider: AWS
- Region: Europe (London)
- EC2 Instance: SOC-Lab-Splunk
- Operating System: Ubuntu Server 24.04 LTS
- Architecture: x86_64
- CPU: 2 vCPU
- RAM: ~8 GB
- Storage: ~29 GB usable
- Swap: 2 GB

### Planned Security Stack

- Splunk Enterprise
- Windows Endpoint
- Sysmon
- Splunk Universal Forwarder
- Security event logs
- Detection rules
- Incident response exercises

## Current Progress

### Week 1 — Infrastructure

- [x] AWS account prepared
- [x] EC2 SOC server created
- [x] Ubuntu Server installed
- [x] SSH access configured
- [x] Server resources verified
- [x] 2 GB swap configured
- [x] EBS volume increased from 8 GB to 30 GB
- [x] Linux partition expanded
- [x] Filesystem expanded to approximately 29 GB
- [x] EC2 instance named `SOC-Lab-Splunk`

### Week 2 — Splunk

- [ ] Install Splunk Enterprise
- [ ] Configure Splunk
- [ ] Enable Splunk Web
- [ ] Create first index
- [ ] Create first searches
- [ ] Begin SOC detection exercises

## Architecture

The initial architecture consists of:

Kali Linux Analyst Machine  
↓  
AWS EC2 SOC Server  
↓  
Splunk Enterprise  
↓  
Windows Endpoint + Sysmon  
↓  
Security Logs  
↓  
SOC Investigation & Detection

## Project Status

**Current Phase:** Week 2 — Splunk Deployment

**Status:** Infrastructure ready for Splunk installation.
