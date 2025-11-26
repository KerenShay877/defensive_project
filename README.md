```markdown
# Maman 15 – MessageU Project

## Overview
MessageU is a secure instant messaging system built for **course 20937 – Defensive Programming**.  
It uses a **client-server model** with **end-to-end encryption**.

- **Server**: Python 3  
- **Client**: C++ (console)  
- **Protocol**: Binary over TCP (little-endian)  
- **Encryption**: RSA (1024-bit) + AES-CBC (128-bit)

---

## Project Layout
```
src/
- server/        # Python server code + myport.info
- client/        # C++ client code + server.info + me.info
```

---

## Libraries Used
### Server (Python)
- `socket` (TCP communication)
- `threading` or `selectors` (multi-client support)
- `struct` (binary packing/unpacking)
- `sqlite3` (bonus: persistent storage)

### Client (C++)
- **Crypto++** (encryption: AES, RSA, Base64)
- `winsock2` or `boost::asio` (TCP communication)
- Standard C++11 STL (`iostream`, `vector`, `string`, etc.)

---

## Running
### Server
```bash
cd src/server
python3 main.py
```

### Client
```bash
cd src/client
g++ -std=c++11 -o client main.cpp
./client
```

---

## Client Menu
```
110) Register
120) Clients list
130) Public key
140) Waiting messages
150) Send text
151) Request symmetric key
152) Send symmetric key
0) Exit
```
---
