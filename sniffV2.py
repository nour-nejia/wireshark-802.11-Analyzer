import sys
from scapy.all import sniff, Dot11

def feature(frame):
    """Fonction qui retourne le type et sous-type de la trame"""
    if frame.haslayer(Dot11):
        frame_type = frame.type
        frame_subtype = frame.subtype
        
        types = {0: "Management", 1: "Control", 2: "Data"}
        type_name = types.get(frame_type, "Unknown")
        
        mgmt_subtypes = {
            0: "Association Request", 1: "Association Response", 
            2: "Reassociation Request", 3: "Reassociation Response", 
            4: "Probe Request", 5: "Probe Response", 
            8: "Beacon", 9: "ATIM",
            10: "Disassociation", 11: "Authentication", 
            12: "Deauthentication", 13: "Action"
        }
        ctrl_subtypes = {
            8: "Block Ack Request", 9: "Block Ack",
            10: "PS-Poll", 11: "RTS", 12: "CTS", 
            13: "ACK", 14: "CF-End", 15: "CF-End+CF-Ack"
        }
        data_subtypes = {
            0: "Data", 1: "Data+CF-Ack", 2: "Data+CF-Poll",
            3: "Data+CF-Ack+CF-Poll", 4: "Null", 5: "CF-Ack",
            6: "CF-Poll", 7: "CF-Ack+CF-Poll", 8: "QoS Data"
        }
        
        if frame_type == 0:
            subtype_name = mgmt_subtypes.get(frame_subtype, f"Unknown({frame_subtype})")
        elif frame_type == 1:
            subtype_name = ctrl_subtypes.get(frame_subtype, f"Unknown({frame_subtype})")
        else:
            subtype_name = data_subtypes.get(frame_subtype, f"Unknown({frame_subtype})")
        
        return type_name, subtype_name
    
    return "No Dot11 layer", ""


def parse(frame): 
    if frame.haslayer(Dot11):
        print("ToDS:", frame.FCfield & 0b1 != 0) 
        print("MF:", frame.FCfield & 0b10 != 0) 
        print("WEP:", frame.FCfield & 0b01000000 != 0) 
        print("src MAC:", frame.addr2) 
        print("dest MAC:", frame.addr1) 
        print("BSSID:", frame.addr3) 
        print("Duration ID:", frame.ID) 
        print("Sequence Control:", frame.SC) 
        
        type_name, subtype_name = feature(frame)
        print("Type:", type_name)
        print("Subtype:", subtype_name) 
        print("\n") 


def main():
    # Vérifier que l'utilisateur a fourni un fichier
    if len(sys.argv) < 2:
        print("Erreur : vous devez fournir un fichier PCAP.")
        print("Exemple : python parse_wifi.py capture.pcap")
        sys.exit(1)

    pcap_file = sys.argv[1]
    print(f"Analyse du fichier : {pcap_file}\n")

    try:
        sniff(offline=pcap_file, prn=parse, store=0)
    except FileNotFoundError:
        print(f" Fichier introuvable : {pcap_file}")
    except Exception as e:
        print(f"Erreur lors de la lecture : {e}")


if __name__ == "__main__":
    main()
