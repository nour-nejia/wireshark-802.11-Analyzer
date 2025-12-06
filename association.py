import sys
from scapy.all import sniff, Dot11
from collections import defaultdict

# Importer la fonction feature depuis sniff3.py
from sniff3 import feature

# Dictionnaire pour stocker les tentatives : {ap_mac: count}
connexions = defaultdict(int)

def parse_association(frame):
    """Parse uniquement les trames Association Request"""
    if frame.haslayer(Dot11):
        frame_type, subtype_name = feature(frame)
        
        # Filtrer uniquement les Association Request
        if subtype_name == "Association Request":
            ap_mac = frame.addr1  # Destination = AP
            connexions[ap_mac] += 1

def main():
    # Vérifier que l'utilisateur a fourni un fichier
    if len(sys.argv) < 2:
        print(" Erreur : Vous devez fournir un fichier PCAP.")
        print("Utilisation : python script.py fichier.pcap")
        sys.exit(1)

    pcap_file = sys.argv[1]

    print(f"Analyse des trames en cours pour : {pcap_file}\n")

    try:
        sniff(offline=pcap_file, prn=parse_association, store=0)
    except FileNotFoundError:
        print(f" Le fichier '{pcap_file}' est introuvable.")
        sys.exit(1)
    except Exception as e:
        print(f" Erreur lors de la lecture du fichier : {e}")
        sys.exit(1)

    # Affichage simple des résultats
    if connexions:
        print("=" * 60) 
        print("TENTATIVES DE CONNEXION PAR POINT D'ACCÈS")
        print("=" * 60 + "\n")
        
        for ap_mac, count in sorted(connexions.items(), key=lambda x: x[1], reverse=True):
            print(f"Point d'accès : {ap_mac}")
            print(f"Nombre de tentatives : {count}")
            print()
        
        print("=" * 60)
        print(f"Total : {sum(connexions.values())} tentatives sur {len(connexions)} points d'accès")
        print("=" * 60)
    else:
        print("Aucune trame Association Request trouvée dans la capture.")

if __name__ == "__main__":
    main()
