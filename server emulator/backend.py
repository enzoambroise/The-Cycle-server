import ssl
import socket
import threading
import logging
import struct
import time 
import sys

# Vérifiez que ce chemin est correct
try:
    import login_response_pb2 
    from google.protobuf.any_pb2 import Any 
except ImportError:
    print("ERREUR: Impossible d'importer login_response_pb2. Avez-vous compilé le .proto ?")
    sys.exit(1)

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

# ---------------- Fonctions de Réponse Protobuf ----------------

def build_nda_response_7_bytes():
    """
    Construit la réponse NDA en format Protobuf NDAResponse seul.
    Taille finale: ~7 bytes.
    """
    try:
        # FIX: Utilise NDAResponse
        nda_response = login_response_pb2.NDAResponse() 
        nda_response.nda = True 
        
        payload = nda_response.SerializeToString()
        return gRPC_frame(payload)
    except AttributeError:
        LOG.error("Erreur: Le message NDAResponse ou le champ 'nda' n'est pas défini. Avez-vous compilé le .proto ?")
        return b''

def build_pong_response_11_bytes():
    """
    Construit le message Pong (11 bytes). Utilisé pour débloquer le client après la NDA.
    """
    try:
        pong = login_response_pb2.Pong()
        # FIX: Utilisera int64 si le .proto a été mis à jour
        pong.server_time_ms = int(time.time() * 1000) 
        
        payload = pong.SerializeToString()
        return gRPC_frame(payload)
    except AttributeError:
        LOG.error("Erreur: Le message Pong n'est pas défini (ou problème int64).")
        return b''

def build_login_response_ok():
    """
    Construit une LoginResponse complète et valide (OK).
    Taille finale: ~92 bytes.
    """
    resp = login_response_pb2.LoginResponse() 
    
    resp.result = login_response_pb2.LoginResponse.Result.OK 
    resp.session_id = "VALID_TOKEN_A7B4C8D2E1F0G3H6I9J4K7L0M3N6P9Q2R5S8T1U4V7W0X3Y6Z9" 
    resp.username = "Enzo_Authorized_User"
    resp.user_id = "user_4567"
    
    payload = resp.SerializeToString()
    return gRPC_frame(payload)

# ---------------- Gestion de la Connexion Client ----------------

def handle_client(connstream, addr):
    """Gère la connexion client : NDA (7b) + PONG (11b) → LoginRequest (Any) → LoginResponse (92b)."""
    LOG.info(f"[{addr}] Connexion TLS établie")
    
    nda_sent = False
    nda_completed = False
    
    try:
        while True:
            # Lecture bloquante pour maintenir la connexion ouverte
            data = connstream.recv(8192) 
            
            if not data:
                LOG.info(f"[{addr}] Le client a fermé la connexion (FIN DE SESSION).")
                break
                
            LOG.info(f"[{addr}] Reçu {len(data)} bytes")
            
            # --- Étape 1: Répondre à la NDA (Requête NDA / 114 bytes) ---
            if b"/nda" in data or b"NDA" in data.upper():
                if not nda_sent:
                    
                    # 1a. Envoi de la NDA nue (7 bytes)
                    resp_nda = build_nda_response_7_bytes()
                    connstream.sendall(resp_nda)
                    LOG.info(f"[{addr}] NDA Response (nu) envoyée ({len(resp_nda)} bytes).")
                    
                    # 1b. Envoi du Pong (11 bytes) pour débloquer le client (Keep-Alive)
                    resp_pong = build_pong_response_11_bytes() 
                    connstream.sendall(resp_pong)
                    LOG.info(f"[{addr}] Pong (11 bytes) envoyé pour débloquer LoginRequest.")
                    
                    nda_sent = True
                    nda_completed = True
                else:
                    LOG.info(f"[{addr}] NDARequest détectée de nouveau, ignorée.")
            
            # --- Étape 2: Répondre au Login (Le client envoie Any<LoginRequest>) ---
            # La détection par le nom du type Protobuf est la plus fiable.
            elif b"type.googleapis.com/LoginRequest" in data:
                if nda_completed:
                    LOG.info(f"[{addr}] LoginRequest encapsulée détectée → envoi LoginResponse OK.")
                    
                    resp = build_login_response_ok() 
                    connstream.sendall(resp)
                    LOG.info(f"[{addr}] LoginResponse envoyée ({len(resp)} bytes). SUCCÈS ! LA CONNEXION EST TERMINÉE.")
                    
                    # Succès, on peut fermer la connexion
                    break 

            else:
                 LOG.info(f"[{addr}] Requête inconnue de {len(data)} bytes (Premiers 50: {data[:50]}), ignorée.")

    except Exception as e:
        LOG.error(f"[{addr}] Erreur inattendue: {e}")
    finally:
        try:
            connstream.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        connstream.close()
        LOG.info(f"[{addr}] Connexion fermée")

def start_tls_server():
    """Initialise et lance le serveur TLS."""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    try:
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    except FileNotFoundError:
        LOG.error(f"ERREUR: Les fichiers TLS ({CERT_FILE} et {KEY_FILE}) sont introuvables. Créez-les avec OpenSSL.")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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