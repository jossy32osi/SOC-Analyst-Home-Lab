# Week 1 — Infrastructure Setup Log

## Objective

Build the cloud infrastructure required for a practical SOC Analyst home lab.

## AWS EC2 Server

An EC2 instance was created for the SOC environment.

- Instance Name: SOC-Lab-Splunk
- Operating System: Ubuntu Server 24.04 LTS
- Architecture: x86_64
- CPU: 2 vCPU
- RAM: approximately 8 GB
- Region: Europe (London)

## SSH Access

SSH access from the Kali Linux analyst machine was successfully established.

## Memory and Swap

The server initially had approximately 7.6 GB of RAM and no swap.

A 2 GB swap file was created to provide additional memory headroom for the lab.

## Storage Expansion

The initial EBS volume was 8 GB.

The volume was increased to 30 GB through AWS EBS volume modification.

The Linux partition and ext4 filesystem were subsequently expanded.

Final usable root filesystem:

- Total: approximately 29 GB
- Used: approximately 4.6 GB
- Available: approximately 24 GB
- Usage: approximately 17%

## Verification

The server was verified after the storage expansion using Linux disk and filesystem commands.

The infrastructure is now ready for deployment of Splunk Enterprise.

## Week 1 Result

**Status: Completed**

The AWS infrastructure required for the SOC Analyst home lab is operational.

## Next Phase

Week 2 will focus on:

1. Splunk Enterprise installation
2. Splunk configuration
3. Splunk Web access
4. Initial log ingestion
5. SPL searches
6. Beginning SOC detection exercises


## Week 2 — Splunk Enterprise Setup

### Splunk Server

Splunk Enterprise 10.4.3 was successfully installed on the AWS EC2 SOC lab server.

Environment:
- OS: Ubuntu Server 24.04 LTS
- Architecture: x86_64
- Splunk version: 10.4.3
- Splunk service account: splunk
- Splunk Web: port 8000
- Splunk management: port 8089
- AWS region: eu-west-2 (London)

### Splunk Configuration

The Splunk Trial license was verified successfully.

- License group: Trial
- Daily indexing allowance: 500 MB
- License expiration: November 4, 2026
- License violations: None
- Licensing warnings: None

A dedicated SOC index was created:

- Index: soc_logs

The index was verified successfully using an event-count search. The result was 0 events because no endpoint has been connected yet.

### Week 2 Status

- [x] Splunk installed
- [x] Splunk service running
- [x] Splunk Web accessible
- [x] Trial license verified
- [x] SOC index created
- [x] SOC index verified
- [ ] Windows endpoint connected
- [ ] Sysmon configured
- [ ] Universal Forwarder configured
