# Lightweight-Multi-Level-Cryptographic-Framework-for-Healthcare-IoT
Designed to secure sensitive patient data in resource-constrained Healthcare IoT (HIoT) environments

## Abstract

The project presents a **lightweight, multi-level cryptographic framework** designed to secure sensitive patient data in resource-constrained **Healthcare IoT (HIoT)** environments. It integrates:

- **PRESENT Cipher** – Lightweight encryption
- **ASCON Cipher** – Authenticated encryption
- **CP-ABE** – Role-based attribute-level access control

The system achieves **<1ms encryption latency**, **<1.5KB memory footprint**, and supports **fine-grained data policies** under healthcare privacy regulations like HIPAA/GDPR.

## Key Objectives

- Efficient lightweight encryption using **PRESENT**
- Authenticated encryption via **ASCON-128 AEAD**
- Dynamic key rotation with **LEAIoT**
- Secure ECC-based key exchange using **brainpoolP256r1**
- Role-based access control with **CP-ABE (Elliptic Curve)**

## Core Components

### PRESENT Cipher
- Block Size: 64 bits
- Keys: 80/128-bit
- RAM usage: <100B
- Throughput: 200–400 Kbps

### ASCON (Sponge Construction)
- State: 320-bit
- Security: 128-bit AEAD
- Features: Lightweight, forgery-resistant, side-channel resistant

### Key Management
- **Hourly key rotation** via LEAIoT
- **Ephemeral session keys** using ECDH (brainpoolP256r1)
- Keys hashed with **SHA3-256 → 80-bit PRESENT key**

### CP-ABE Access Control
- Attribute-based encryption
- Fine-grained policies:
  - E.g., `role:doctor AND department:cardiology`
- ECC-optimized for IoT


## How to Run

1. Clone the repository.
2. Install dependencies:
   ```bash
   pip install streamlit pandas pycryptodome tinyec psutil
4. Open your terminal or command prompt and run:
   ```bash
   streamlit run CODEFILE.py


## Contact

For any queries, suggestions or contributions, feel free to reach out: urmimirani27841@gmail.com
