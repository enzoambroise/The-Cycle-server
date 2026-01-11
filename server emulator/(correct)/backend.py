import ssl
import socket
import threading
import logging
import struct
import sys
from google.protobuf.any_pb2 import Any 

try:
    import login_response_pb2 
except ImportError:
    print("ERREUR: Fichier login_response_pb2.py introuvable.")
    sys.exit(1)

# ---------------- CONFIGURATION ----------------
LOG = logging.getLogger("TLS-MOCK")
logging.basicConfig(level=logging.INFO, format="%(asctime)s:%(levelname)s:%(message)s")

CERT_FILE = "server.crt"
KEY_FILE = "server.key"
LISTEN_HOST = "0.0.0.0" 
LISTEN_PORT = 50051

# La taille totale que le jeu attend (Préambule inclus)
TARGET_TOTAL_SIZE = 1305
# ----------------------------------------------

def build_mega_login_response():
    """
    Construit la réponse avec le préambule de longueur (Little Endian).
    Taille cible : 4 octets (longueur) + X octets (payload) = 1305.
    """
    resp = login_response_pb2.LoginResponse() 
    resp.result = login_response_pb2.LoginResponse.Result.OK
    resp.user_id = "4567890123"
    resp.username = "Enzo_User"
    resp.session_id = "TOKEN_FOR_LOGIN" 
    resp.is_initialized = True 
    
    # Le payload seul doit faire 1301 octets pour que Total soit 1305
    PAYLOAD_TARGET = TARGET_TOTAL_SIZE - 4
    p7_padding_size = 900 

    for _ in range(15):
        resp.large_init_packet = b'X' * p7_padding_size 
        
        any_msg = Any()
        any_msg.Pack(resp)
        # On force l'URL de type si nécessaire (optionnel)
        # any_msg.type_url = "type.googleapis.com/LoginResponse"
        
        payload = any_msg.SerializeToString()
        current_len = len(payload)
        
        if current_len == PAYLOAD_TARGET:
            # Framing : Longueur sur 4 octets en Little Endian (ex: 15 05 00 00)
            header = struct.pack("<I", current_len)
            LOG.info(f"Payload Protobuf: {current_len} octets. Header: {header.hex()}")
            return header + payload
        
        diff = PAYLOAD_TARGET - current_len
        p7_padding_size += diff
        
    return struct.pack("<I", len(payload)) + payload

def handle_client(connstream, addr):
    LOG.info(f"[{addr}] Nouvelle connexion client établie.")
    
    try:
        # 1. Réception de la requête du jeu
        data = connstream.recv(4096)
        if not data:
            return

        LOG.info(f"[{addr}] REÇU ({len(data)} octets): {data.hex()[:64]}...")

        # 2. Analyse et Réponse
        if b"LoginRequest" in data:
            LOG.info(f"[{addr}] LoginRequest détectée. Envoi du paquet de {TARGET_TOTAL_SIZE} octets...")
            
            full_packet = build_mega_login_response()
            connstream.sendall(full_packet)
            
            LOG.info(f"[{addr}] Réponse envoyée. En attente de la suite (Lobby)...")

            # 3. Observation : On ne coupe pas la connexion
            connstream.settimeout(30.0) 
            while True:
                try:
                    next_data = connstream.recv(4096)
                    if not next_data:
                        LOG.info(f"[{addr}] Le client a fermé la connexion.")
                        break
                    LOG.info(f"[{addr}] NOUVELLE REQUÊTE DU JEU : {next_data.hex()}")
                except socket.timeout:
                    LOG.info(f"[{addr}] Timeout : Pas de nouvelle requête après 30s.")
                    break
        else:
            LOG.warning(f"[{addr}] Requête inconnue (pas de LoginRequest).")

    except Exception as e:
        LOG.error(f"[{addr}] Erreur : {e}")
    finally:
        LOG.info(f"[{addr}] Fermeture de la connexion.")
        connstream.close()

def run_tls_server():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    try:
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    except Exception as e:
        LOG.error(f"Erreur de chargement des certificats : {e}")
        return

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((LISTEN_HOST, LISTEN_PORT))
    server_sock.listen(10)
    
    LOG.info(f"[TLS-MOCK] Prêt sur le port {LISTEN_PORT}. En attente du jeu...")

    try:
        while True:
            newsock, addr = server_sock.accept()
            try:
                connstream = context.wrap_socket(newsock, server_side=True)
                threading.Thread(target=handle_client, args=(connstream, addr), daemon=True).start()
            except Exception as e:
                LOG.error(f"Erreur SSL Handshake : {e}")
                newsock.close()
    except KeyboardInterrupt:
        LOG.info("Arrêt du serveur.")
    finally:
        server_sock.close()

if __name__ == "__main__":
    run_tls_server()