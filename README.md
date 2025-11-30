# ePacket Base

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-purple?style=for-the-badge)
![Meshtastic](https://img.shields.io/badge/Meshtastic-Packet%20Monitor-orange?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

---

ePacket Base is a standalone Meshtastic packet-monitoring tool for reading live serial traffic, inspecting decoded packets, tracking nodes, and analyzing mesh activity.  
Built for operators who want raw visibility into their network without the noise, cloud dependencies, or telemetry clutter that hides what’s actually happening on the mesh.

---

## Features

- **Real-time Serial Feed**  
  Everything your Meshtastic device outputs shows up instantly.

- **Packet Inspector**  
  Full JSON breakdown of the last packet, including portnum, telemetry, and raw payload.

- **Node Table**  
  Lists all nodes heard, with ID and last-heard timestamp.

- **Message Log**  
  Text messages are pulled out and displayed cleanly in their own view.

- **Simple Connect UI**  
  Select COM port → Connect → Done.

- **No Internet Required**  
  100% offline. Pure serial. Pure data.

---

## Screenshot

Add your UI image here:

images/epacket_base_ui.png

yaml
Copy code

Markdown embed:

![ePacket Base UI](images/epacket_base_ui.png)

---

## Installation

Clone the repo:


git clone https://github.com/YOUR-USERNAME/epacket-base.git
cd epacket-base
Install dependencies:

bash
Copy code
pip install -r requirements.txt
Connect your Meshtastic device via USB.

Running
Start the program:

bash
Copy code
python epacket_base.py
Pick your COM port

Press Connect

Watch packets flow

What You Can Do With the Data
Analyze mesh health

View channel traffic

Capture telemetry from field units

Watch route rebuilding and retries

Inspect RSSI/SNR for range testing

Reverse-engineer or debug custom firmware

Monitor a busy mesh in real time

ePacket Base shows all packets — even the ones apps usually hide.

Roadmap
Packet filtering

File logging (JSON and CSV)

Color-coded message types

Node alias system

Optional GPS heatmap mode

License
Released under the MIT License.

Author
Gary Erwin
Creator of ePacket Base
