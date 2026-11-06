# 🦉 ODropper

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Attack%20/%20Offensive-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **ODropper** — Stager/dropper analyzer — stages, decode, sandbox-evasion markers ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

ODropper — Stager/dropper analyzer — stages, decode, sandbox-evasion markers. Stager/dropper static analyzer (offline; nothing is executed or fetched). Analyze dropper/stager behavior (simulated), stages, decode, sandbox-evasion markers; benign generator patterns for labs.

---

## ✨ Features

- Analyze stager/dropper samples for multi-stage delivery chains
- Decode common embedding and obfuscation layers
- Flag sandbox-evasion and environment-check markers
- Map observed behaviors to likely next-stage payloads
- Offline-first workflow with cyan interactive UI
- Export structured findings for malware-analysis notes

---

## ⚙️ Requirements

- **Linux**
- **Go 1.21+** (stdlib only; `CGO_ENABLED=0`)

---

## 🚀 Usage

```bash
go build -ldflags="-s -w" -o ODropper ODropper.go
./ODropper --help
./ODropper --input sample.bin
./ODropper --input stager.bin --format json --output report.json
./ODropper --demo
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad
