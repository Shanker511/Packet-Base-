![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-purple?style=for-the-badge)
![Meshtastic](https://img.shields.io/badge/Meshtastic-Packet%20Monitor-orange?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

# Packet Base

Packet Base is a desktop **Meshtastic packet console** built with Python and Tkinter.

It connects to a Meshtastic node over USB serial and gives you a clean, cyberpunk-style
view of what your radio is doing:

- Live **serial / router logs** from the node
- Decoded **Meshtastic packets** with RSSI / SNR
- A searchable table of **seen nodes**
- A **message list** showing who talked to who on which channel
- Raw **JSON view** of the last packet if you want to feed it into other tools

No database. No cloud. Just you and the RF.

---

## Features

- 🛰 **Serial / Packet Feed**  
  Left pane shows all log lines coming off the radio plus a one-line summary
  for each decoded packet (TEXT, POS, TELEMETRY, etc).

- 👥 **Nodes Tab**  
  Lists every node your radio has seen on the mesh with node ID, name, and
  last-heard time.

- 💬 **Messages Tab**  
  Shows text messages with timestamp, channel, source, destination, and a
  truncated preview.

- 🧱 **Raw JSON Detail**  
  Bottom-left pane shows the full decoded Meshtastic packet as JSON for the
  last packet received.

- 📡 **TX Support**  
  Simple “Channel + Send” bar at the bottom to broadcast messages from your
  connected node.

---


## Requirements

- **OS:** Windows, macOS, or Linux  
- **Python:** 3.10+ recommended
- A Meshtastic-compatible device connected over USB (T-Beam, Heltec, RAK, etc.)

Python packages:

- `meshtastic`
- `pyserial`
- `pypubsub`

You can install them from `requirements.txt` or manually (see below).

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-user/epacket-base.git
cd epacket-base
Author

Gary Erwin
Creator of ePacket Base
