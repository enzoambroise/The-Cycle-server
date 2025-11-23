import ssl
import socket
import threading
import logging
import json
import struct
import sys
import time 

import login_response_pb2 
from google.protobuf.any_pb2 import Any # <-- NOUVEL IMPORT CRITIQUE

# ---------------- CONFIGURATION ----------------
LOG = logging.getLogger("TLS-MOCK")
logging.basicConfig(level=logging.INFO, format="%(asctime)s:%(levelname)s:%(message)s")

CERT_FILE = "server.crt"
KEY_FILE = "server.key"
LISTEN_HOST = "0.0.0.0" 
LISTEN_PORT = 50051
# -----------------------------------------------

def gRPC_frame(payload):
    """Encapsule les données Protobuf avec le framing gRPC."""
    return b"\x00" + struct.pack(">I", len(payload)) + payload

def build_login_response():
    """Construit une LoginResponse simple et valide (92 bytes, OK)."""
    resp = login_response_pb2.LoginResponse() 
    
    resp.result = login_response_pb2.LoginResponse.Result.OK 
    resp.session_id = "VALID_TOKEN_A7B4C8D2E1F0G3H6I9J4K7L0M3N6P9Q2R5S8T1U4V7W0X3Y6Z9" 
    resp.username = "Enzo_Authorized_User"
    resp.user_id = "user_4567"
    
    payload = resp.SerializeToString()
    return gRPC_frame(payload)

# CODE DE TEST CRITIQUE POUR build_nda_protobuf_response

def build_nda_protobuf_response():
    """Construit la réponse NDA en envoyant le message NDAStatus seul."""
    
    nda_status = login_response_pb2.NDAStatus()
    # 💥 CHANGEMENT : Assigner la valeur à 'nda'
    nda_status.nda = True 
    
    payload = nda_status.SerializeToString()
    return gRPC_frame(payload)

def handle_client(connstream, addr):
    """Gère la connexion client et la séquence NDA/Login."""
    LOG.info(f"[{addr}] Connexion TLS établie")
    try:
        data = connstream.recv(8192) 
        if not data:
            LOG.info(f"[{addr}] Client a fermé la connexion sans envoyer de données.")
            return

        LOG.info(f"[{addr}] Reçu {len(data)} bytes")
        
        # --- Détection et Réponse NDA (1ère étape critique) ---
        if b"/nda" in data or b"NDA" in data.upper():
            LOG.info(f"[{addr}] NDARequest détectée → envoi NDA mock PROTOBUF.")
            
            resp = build_nda_protobuf_response() 
            connstream.sendall(resp)
            LOG.info(f"[{addr}] NDA Response envoyée ({len(resp)} bytes).")
            
            time.sleep(0.01) 
            
            # Tente de lire à nouveau pour la LoginRequest (bloquant)
            new_data = connstream.recv(8192) 
            
            if new_data:
                data = new_data
                LOG.info(f"[{addr}] Nouvelle requête (LoginRequest) reçue après NDA: {len(data)} bytes.")
            else:
                 LOG.info(f"[{addr}] Le client a fermé la connexion après NDA.")
                 return 

        # --- Détection et Réponse Login (2ème étape critique) ---
        if b"type.googleapis.com/LoginRequest" in data:
            LOG.info(f"[{addr}] LoginRequest détectée → envoi LoginResponse VRAI.")
            resp = build_login_response() 
            connstream.sendall(resp)
            LOG.info(f"[{addr}] LoginResponse envoyée ({len(resp)} bytes).")
            
        else:
             LOG.info(f"[{addr}] Message inconnu, ou Login non détecté dans le dernier paquet.")

    except Exception as e:
        LOG.exception(f"[{addr}] Erreur lors du traitement du client: {e}")
    finally:
        try:
            connstream.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        connstream.close()
        LOG.info(f"[{addr}] Connexion fermée")

def start_tls_server():
    """Initialise et démarre le serveur TLS."""
    
    # ... (Vérification Protobuf et chargement des certificats - PAS CHANGÉ)
    try:
        _ = login_response_pb2.LoginResponse()
    except AttributeError:
        LOG.error("ERREUR: Le module 'login_response_pb2' n'a pas pu être initialisé.")
        LOG.error("Assurez-vous d'avoir exécuté: protoc --python_out=. login_response.proto")
        sys.exit(1)
        
    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    except FileNotFoundError:
        LOG.error(f"ERREUR: Les fichiers TLS ({CERT_FILE} et {KEY_FILE}) sont introuvables. Créez-les avec OpenSSL.")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # ... (bind et listen)
    try:
        sock.bind((LISTEN_HOST, LISTEN_PORT))
    except OSError as e:
        LOG.error(f"ERREUR lors du bind sur {LISTEN_HOST}:{LISTEN_PORT}. Le port est-il déjà utilisé ?")
        return
        
    sock.listen(8)
    LOG.info(f"[TLS-MOCK] Serveur TLS à l'écoute sur {LISTEN_HOST}:{LISTEN_PORT}")

    try:
        while True:
            newsock, addr = sock.accept()
            try:
                connstream = context.wrap_socket(newsock, server_side=True)
                t = threading.Thread(target=handle_client, args=(connstream, addr), daemon=True)
                t.start()
            except ssl.SSLError as se:
                LOG.error(f"[{addr}] Échec de la poignée de main TLS: {se}")
                newsock.close()
    except KeyboardInterrupt:
        LOG.info("Arrêt serveur TLS demandé")
    finally:
        sock.close()

if __name__ == "__main__":
    start_tls_server()