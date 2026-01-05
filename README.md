# 🗳️ Secure National Election & Voting Management System

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-black)
![Security](https://img.shields.io/badge/Security-Cryptography-red)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen)
![License](https://img.shields.io/badge/License-Academic-orange)

> **Empowering Democracy Through Secure, Transparent & Tamper-Proof Digital Voting**

---

## 📌 Project Overview

The **Secure National Election & Voting Management System** is a **high-security Flask-based web application** designed to conduct digital elections with **maximum confidentiality, integrity, and authenticity**.

This system is built with **security-first architecture**, implementing **custom cryptographic algorithms from scratch** (RSA, ECC, HMAC) without relying on built-in encryption libraries.

All sensitive data is **encrypted before storage**, protected by **multi-level asymmetric encryption**, **two-factor authentication**, **secure session management**, and **role-based access control**.

---

## 🚀 Key Highlights

- 🔐 **Multi-Level Encryption (RSA + ECC)**
- 🧠 **All Cryptographic Algorithms Implemented From Scratch**
- 🔑 **Per-User Key Management & Automatic Key Rotation**
- 🔒 **Two-Factor Authentication (OTP via Email)**
- 🛡️ **HMAC & CBC-MAC for Data Integrity**
- 👥 **Role-Based Access Control (Admin / Voter)**
- 🧾 **Encrypted Database Storage (Zero Plaintext)**
- 🧑‍💻 **Secure Session Handling with Hijacking Protection**

---
## 🏗️ System Architecture

Client Browser
│
▼
Flask Application
┌───────────────┐
│ Routes │
│ (Blueprints) │
└──────┬────────┘
▼
┌───────────────┐
│ Middleware │
│ RBAC + Crypto │
└──────┬────────┘
▼
┌───────────────┐
│ Crypto Layer │
│ RSA | ECC | │
│ HMAC | Hash │
└──────┬────────┘
▼
┌───────────────┐
│ SQLite DB │
│ (Encrypted) │
└───────────────┘


---

## 🔐 Security Features

### ✅ Authentication & Authorization
- Username & Password authentication
- **OTP-based Two-Factor Authentication**
- Account lockout after 5 failed attempts
- Role-based access control (RBAC)

### ✅ Cryptography (From Scratch)
| Component | Algorithm |
|--------|----------|
| Password Hashing | SHA-256 + Salt + 100k Iterations |
| Encryption | RSA (2048-bit) |
| Secondary Encryption | ECC (secp256k1) |
| Integrity Check | HMAC-SHA256 + CBC-MAC |

### ✅ Multi-Level Encryption Flow
Plaintext
↓
RSA Encryption
↓
ECC Encryption
↓
Encrypted Ciphertext (Stored)

---

## 🔑 Key Management System

- Unique RSA + ECC key pair **per user**
- Secure key storage with versioning
- Automatic **90-day key rotation**
- Old keys safely retired with backup versions

---

## 🛡️ Secure Session Management

- 64-byte cryptographically secure session tokens
- Tokens **hashed before database storage**
- IP & User-Agent validation
- Session hijacking detection
- Automatic session expiration

---

## 📂 Project Structure

SecureVotingSystem/
├── app.py
├── config.py
├── requirements.txt
│
├── auth/ # Authentication & Sessions
├── crypto/ # RSA, ECC, HMAC, Hashing
├── key_management/ # Key generation & rotation
├── middleware/ # RBAC & Encryption middleware
├── models/ # Database models
├── routes/ # Flask blueprints
├── templates/ # Jinja2 templates
├── static/ # CSS, JS, images
└── database/
└── voting_system.db

## ⚙️ Installation & Setup

### 1️⃣ Install Dependencies
---pip install -r requirements.txt

### 2️⃣ Run the Application
python app.py

### 3️⃣ Access the System
http://127.0.0.1:5000

## 📌 Note: In development mode, OTPs are also printed in the console.



