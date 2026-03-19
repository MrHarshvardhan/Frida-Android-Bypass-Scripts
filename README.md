# Android Root Detection & SSL Pinning Bypass (Frida Scripts)

## Overview

This repository contains Frida scripts for bypassing common Android security controls during mobile application security testing.

The scripts are designed for:

* Root detection bypass
* SSL pinning bypass
* Proxy detection bypass
* Debugging and instrumentation support

These scripts are intended for **authorized security testing and research purposes only**.

---

## Features

* Bypass multiple root detection techniques (Java + Native)
* Disable SSL pinning (OkHttp, TrustManager, WebView, etc.)
* Works on both rooted and non-rooted devices (via Frida server / gadget)
* Easy to plug into existing mobile pentest workflow
* Modular scripts (use individually or combine)

---

## Requirements

Make sure you have the following setup:

* Frida (latest version recommended)
* Android device / emulator
* ADB configured
* Burp Suite / proxy (for SSL interception)
* Basic understanding of Frida hooks

Install Frida:

```bash
pip install frida-tools
```

---

## Setup

### 1. Start Frida Server (on device)

```bash
adb push frida-server /data/local/tmp/
adb shell "chmod +x /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

### 2. Verify Connection

```bash
frida-ps -U
```

---

## Usage

### Spawn App with Script

```bash
frida -U -f com.target.app -l script.js --no-pause
```

### Attach to Running App

```bash
frida -U -n com.target.app -l script.js
```

### Remote Frida (example)

```bash
frida -H 127.0.0.1:4444 -f com.target.app -l script.js
```

---

## Scripts Included

| Script Name     | Description                         |
| --------------- | ----------------------------------- |
| root_bypass.js  | Bypass common root detection checks |
| ssl_bypass.js   | Universal SSL pinning bypass        |
| proxy_bypass.js | Bypass proxy detection              |
| debug_bypass.js | Disable debugger checks             |

---

## Common Bypasses Covered

### Root Detection

* Build tags check
* su binary detection
* BusyBox detection
* Magisk detection
* System properties

### SSL Pinning

* OkHttp CertificatePinner
* TrustManager
* WebView SSL checks
* Custom implementations

---

## Burp Configuration

1. Set proxy on device
2. Install Burp CA certificate
3. Run SSL bypass script
4. Intercept traffic

---

## Troubleshooting

### App Crashes on Start

* Try attaching instead of spawning
* Use delayed hooks (`setTimeout`)
* Check logcat

### SSL Still Not Bypassed

* App may use native pinning
* Combine multiple scripts
* Use Objection or custom hooks

### Frida Not Detecting Device

```bash
adb devices
frida-ps -U
```

---

## Disclaimer

This repository is for educational and authorized penetration testing only.
Do not use these scripts on applications without proper permission.

---

## Contribution

Feel free to submit PRs with:

* New bypass techniques
* Improvements to existing scripts
* Support for new frameworks

---

## Author

Harsh – Offensive Security Specialist
