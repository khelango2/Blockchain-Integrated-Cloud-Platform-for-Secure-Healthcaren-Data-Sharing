# Blockchain-Integrated Cloud Platform for Secure Healthcare Data Sharing

A secure healthcare data management system that combines blockchain technology with cloud infrastructure to ensure encrypted storage, tamper-proof audit logs, and patient-controlled access to medical records.

## Overview
Traditional cloud-based healthcare systems suffer from weak access control, data tampering risks, and poor auditability. This platform addresses those issues by:

- Encrypting medical records using **Fernet (AES-based)** encryption before cloud storage
- Generating **SHA-256 hashes** to verify data integrity
- Using **Solidity smart contracts** (simulated via Hardhat) for decentralized access control
- Allowing **patients to approve/reject** doctor access requests
- Maintaining **immutable audit logs** for full traceability
- Supporting **role-based access** for Patients, Doctors, and Admins

## Tech Stack
- **Backend:** Python, Flask
- **Blockchain:** Solidity, Hardhat (simulated environment)
- **Encryption:** Fernet (cryptography library), SHA-256
- **Frontend:** Web/Mobile portal
- **Database:** SQLite / File-based storage (simulated cloud)

## Compliance
Designed with HIPAA and GDPR standards in mind.

## Academic Context
Final Year Project — B.Tech CSE (IoT & Cyber Security)  
Siddharth Institute of Engineering & Technology, Puttur (2025–26)
