# Secure Drone Command Server (Python)

## Overview
This project simulates a **drone command server** with **encrypted communication** between a control station and a drone. The server receives commands (like "takeoff" or "land"), decrypts them using **AES-CBC encryption**, executes the simulated command, and sends an encrypted response back.

This is a **prototype project** designed to demonstrate understanding of:
- Networking with sockets (`socket`)
- Symmetric encryption (`AES` with PyCryptodome)
- Basic drone command simulation

---

## Current Features
- TCP socket server that listens for incoming commands
- Secure client-server communication using **ECDH** key agreenment
- Session key derivation using **HKDF (SHA-256)**
- Encrypted command and response messages using **AES-GCM**
- Supports commands:
  - `takeoff` → simulates drone taking off
  - `land` → simulates drone landing
  - Any other command → marked as unknown
- Sends encrypted responses back to the client

## Next Updates
- Integrate **Microsoft AirSim** to simulate real drone movement
- Add **intrusion detection** for suspicious commands
- Optional: Build a **Flask dashboard** to control the drone visually

