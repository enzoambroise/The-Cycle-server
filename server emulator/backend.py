import socket
import ssl
import logging
import json
# Importez le module Protobuf généré
from login_response_pb2 import LoginResponse, LoginResponse_Result
# NOUVELLE IMPORTATION : Importez Any pour encapsuler le message
from google.protobuf.any_pb2 import Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

PORT = 50051
HOST = "127.0.0.1"

CERT_FILE = 'server.crt'
KEY_FILE = 'server.key'

def handle_client(connstream):
    try:
        # Tente de lire l'en-tête de 4 octets du jeu (si présent)
        # Le jeu envoie 91000000 devant son LoginRequest. On le lit au cas où,
        # mais le backend ne devrait probablement pas renvoyer cet en-tête pour la LoginResponse.
        header = connstream.recv(4)
        if not header:
            logging.info("Client déconnecté (lecture de l'en-tête initiale).")
            return
        logging.info(f"En-tête de 4 octets reçu du client : {header.hex()}")

        # Tente de lire le reste des données Protobuf (LoginRequest encapsulé dans Any)
        # La stratégie de lecture peut nécessiter des ajustements (par ex. lire la longueur si envoyée)
        # Pour l'instant, lecture avec timeout pour capturer un message complet.
        data_chunks = []
        connstream.settimeout(0.5) # Temps d'attente court pour la lecture
        while True:
            try:
                chunk = connstream.recv(4096)
                if not chunk:
                    break # Connexion fermée ou plus de données
                data_chunks.append(chunk)
            except socket.timeout:
                break # Timeout, fin de la réception des données
        
        full_data = b''.join(data_chunks)
        if not full_data:
            logging.warning("Aucune donnée Protobuf du client reçue (après l'en-tête).")
            return

        logging.info(f"Données Protobuf brutes reçues du client : {full_data.hex()}")

        # *** Partie cruciale : Construction et envoi de la LoginResponse ***
        login_response = LoginResponse()
        login_response.result = LoginResponse_Result.OK
        login_response.session_id = "mock_session_id_12345"
        login_response.username = "MockPlayerName" # Assurez-vous que ce nom est acceptable par le jeu
        login_response.user_id = "mock_user_id_ABCDE" # Assurez-vous que cet ID est acceptable par le jeu
        
        # NOUVEAU : Encapsuler la LoginResponse dans un message Any
        any_message = Any()
        any_message.Pack(login_response) # Pack la LoginResponse dans l'Any message

        # Sérialiser le message Any
        serialized_any_response = any_message.SerializeToString()
        
        # Envoyer le message Any sérialisé au client
        # Nous n'ajoutons PAS l'en-tête 91000000 ici, car le code Ghidra montre Any::UnpackTo()
        # qui s'attend au message Any lui-même.
        connstream.sendall(serialized_any_response)
        logging.info(f"LoginResponse (encapsulée dans Any) envoyée ({len(serialized_any_response)} octets).")

    except socket.error as e:
        logging.error(f"Erreur de socket : {e}")
    except ssl.SSLError as e:
        logging.error(f"Erreur SSL dans handle_client : {e}")
    except Exception as e:
        logging.error(f"Erreur inattendue dans handle_client : {e}")
    finally:
        try:
            connstream.shutdown(socket.SHUT_RDWR)
        except OSError as e:
            logging.warning(f"Erreur lors de l'arrêt de la connexion (peut-être déjà fermée) : {e}")
        connstream.close()

# Reste du code du serveur (main loop) inchangé
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(CERT_FILE, KEY_FILE)
context.minimum_version = ssl.TLSVersion.TLSv1_2 # Assurez-vous que le jeu supporte cette version ou ajustez

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bindsocket:
        bindsocket.bind((HOST, PORT))
        bindsocket.listen(1)
        logging.info(f"Serveur TCP/SSL Backend démarré sur {HOST}:{PORT}. En attente de connexions...")
        
        while True:
            newsocket, fromaddr = bindsocket.accept()
            logging.info(f"Nouvelle connexion TCP entrante de : {fromaddr}")
            try:
                connstream = context.wrap_socket(newsocket, server_side=True)
                handle_client(connstream)
            except ssl.SSLError as e:
                logging.error(f"Erreur SSL lors du handshake client (probablement un problème de certificat ou de version TLS) : {e}")
                newsocket.close()
            except Exception as e:
                logging.error(f"Erreur lors de l'établissement de la connexion SSL : {e}")
                newsocket.close()
except FileNotFoundError:
    logging.error(f"Le certificat '{CERT_FILE}' ou la clé '{KEY_FILE}' est introuvable.")
    logging.error("Assurez-vous qu'ils sont dans le même répertoire que le script ou que les chemins sont corrects.")
    logging.error("Générez-les avec OpenSSL (voir instructions précédentes).")
except ssl.SSLError as e:
    logging.error(f"Erreur SSL lors du chargement du certificat : {e}")
    logging.error("Vérifiez la validité de votre certificat et de votre clé (phrase secrète si vous en avez mis une).")
except KeyboardInterrupt:
    logging.info("\nServeur TCP/SSL Backend arrêté.")
except Exception as e:
    logging.error(f"Une erreur inattendue dans le serveur principal : {e}")
finally:
    if 'bindsocket' in locals() and bindsocket._closed == False:
        bindsocket.close()