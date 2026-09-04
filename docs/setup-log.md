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
