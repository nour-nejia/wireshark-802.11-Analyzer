# Wireshark Analyzer 802.11

802.11 (Wi-Fi) frame analyzer for Wireshark capture files (.pcap). This project contains three analysis tools to examine different aspects of wireless frames.

## Description

This project provides three Python scripts to analyze Wi-Fi packet captures:
- **sniffV1**: Column-based display of essential frame information
- **sniffV2**: Detailed block-based display of each frame
- **association**: Analysis of association attempts to access points

## Prerequisites

- Python 3.x
- Scapy (`pip install scapy`)
- A Wireshark capture file (.pcap) containing 802.11 frames

## Installation

1. Clone this repository:
```bash
git clone https://github.com/your-username/wireshark-analyzer-802.11.git
cd wireshark-analyzer-802.11
```

2. Install dependencies:
```bash
pip install scapy
```

##  Usage

### sniffV1 - Column Display

Displays frames in a table format with Type, Subtype, TA (Transmitter Address), RA (Receiver Address), SA (Source Address), and DA (Destination Address).

**Execution:**
```powershell
cd "path\to\wireshark-analyzer-802.11"
python sniffV1.py --pcap myfile.pcap
```

**Sample output:**
```
802.11 | Type          | Subtype    | TA                | RA                | SA                | DA
```

### sniffV2 - Detailed Block Display

Displays each frame in block format with all available details.

**Execution:**
```powershell
cd "path\to\wireshark-analyzer-802.11"
python sniffV2.py myfile.pcap
```

**Sample output:**
```
========================================
Frame #1
========================================
ToDS: False
MF: False
WEP: False
src MAC: 00:16:b6:f7:1d:51
dest MAC: ff:ff:ff:ff:ff:ff
BSSID: 00:16:b6:f7:1d:51
Duration ID: 0
Sequence Control: 61168
Type: Management
Subtype: Beacon
```

### association - Association Attempts Analysis

Counts the number of association attempts for each access point and displays the global total.

**Execution:**
```powershell
cd "path\to\wireshark-analyzer-802.11"
python association.py myfile.pcap
```

**Sample output:**
```
Access Point: 00:16:b6:f7:1d:51 - Attempts: 5
Access Point: aa:bb:cc:dd:ee:ff - Attempts: 3

Total association attempts: 8 for 2 access points 
```

## Project Structure

```
wireshark-analyzer-802.11/
│
├── sniffV1.py              # Column format analyzer
├── sniffV2.py              # Block format analyzer
├── association.py          # Association analyzer
├── Wireshark.pcap            # Example file for testing
└── README.md              # This file
```

##  Testing with Example File

An example capture file (`Wireshark.pcap`) is provided to test the scripts:

```powershell
cd "path\to\folder"
python sniffV1.py --pcap Wireshark.pcap
python sniffV2.py Wireshark.pcap
python association.py Wireshark.pcap
```

## 802.11 Frame Information

### Analyzed Fields:
- **Type**: Frame type (Management, Control, Data)
- **Subtype**: Specific subtype (Beacon, Probe Request, Association Request, etc.)
- **ToDS/FromDS**: Frame direction
- **TA**: Transmitter Address
- **RA**: Receiver Address
- **SA**: Source Address
- **DA**: Destination Address
- **BSSID**: Access point identifier
- **MF**: More Fragments flag
- **WEP**: WEP encryption enabled

## Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.
