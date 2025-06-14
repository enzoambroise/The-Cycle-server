import socket
import ssl
import logging
import json
# Importez le module Protobuf généré
from login_response_pb2 import LoginResponse, LoginResponse_Result #

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s') #

PORT = 50051 #
HOST = "127.0.0.1" #

CERT_FILE = 'server.crt' #
KEY_FILE = 'server.key' #

def decode_protobuf_message(data): #
    """
    Tente de décoder un message Protobuf (LoginRequest) et d'extraire des champs.
    """
    decoded_info = {} #
    try: #
        # Ignorer les 4 premiers octets (91000000) de l'en-tête de protocole du jeu
        protobuf_payload = data[4:] #

        # On sait que c'est un LoginRequest, mais on n'a pas son .proto.
        # On va juste extraire les strings qu'on a déjà identifiées.
        start_type = protobuf_payload.find(b'type.googleapis.com/LoginRequest') #
        if start_type != -1: #
            decoded_info['message_type'] = 'LoginRequest' #

        start_jwt = protobuf_payload.find(b'your_simulated_jwt_token_for_nda_acceptance') #
        if start_jwt != -1: #
            jwt_end_index = start_jwt + len(b'your_simulated_jwt_token_for_nda_acceptance_12345ABCDEF_GHIKLMNO') #
            decoded_info['jwt'] = protobuf_payload[start_jwt:jwt_end_index].decode('utf-8') #

        start_version = protobuf_payload.find(b'PROSPECT/Releases/') #
        if start_version != -1: #
            version_start = start_version - 10 #
            version_end = start_version + len(b'PROSPECT/Releases/RL_01') #
            decoded_info['client_version'] = protobuf_payload[version_start:version_end].decode('utf-8') #

    except Exception as e: #
        logging.warning(f"Erreur lors du décodage simplifié des données Protobuf : {e}") #
    return decoded_info #


def handle_client(connstream): #
    logging.info(f"Connexion TCP/SSL établie avec : {connstream.getpeername()}") #
    try: #
        while True: #
            data = connstream.recv(4096) #
            if not data: #
                break #

            logging.info(f"Données reçues (brutes) : {data.hex()}") #
            logging.info(f"Taille des données reçues : {len(data)} octets") #

            decoded_request = decode_protobuf_message(data) #
            logging.info(f"Requête Protobuf décodée : {decoded_request}") #

            # --- Construction de la réponse Protobuf pour LoginResponse ---
            response = LoginResponse() #
            response.result = LoginResponse_Result.OK # Définit le statut à OK

            # Remplissez les autres champs avec des valeurs mockées
            response.session_id = "mock_session_12345" #
            response.username = "MockPlayer" #
            response.user_id = "mock_user_abcde" #

            # Sérialisez le message Protobuf en octets
            protobuf_payload = response.SerializeToString() #
            
            # AJOUT DE LA LIGNE POUR VOIR LE PAYLOAD PROTBUF GÉNÉRÉ
            logging.info(f"Payload Protobuf généré (hex) : {protobuf_payload.hex()}") #

            # Ajouter l'en-tête de protocole du jeu (les 4 premiers octets, 92000000)
            response_data = b'\x92\x00\x00\x00' + protobuf_payload #
            
            connstream.sendall(response_data) #
            logging.info(f"Réponse envoyée (brute) : {response_data.hex()}") #
            logging.info("-" * 80) #

    except ssl.SSLError as e: #
        logging.error(f"Erreur SSL pendant la communication avec le client : {e}") #
    except socket.error as e: #
        logging.error(f"Erreur de socket pendant la communication avec le client : {e}") #
    except Exception as e: #
        logging.error(f"Erreur inattendue pendant le traitement du client : {e}") #
    finally: #
        connstream.close() #
        logging.info("Connexion client fermée.") #

def run_server(): #
    bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #
    bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #
    bindsocket.bind((HOST, PORT)) #
    bindsocket.listen(5) #

    logging.info(f"Serveur TCP/SSL Backend démarré sur HTTPS://{HOST}:{PORT}") #
    logging.info(f"Assurez-vous que '{CERT_FILE}' et '{KEY_FILE}' sont dans le même répertoire.") #
    logging.info("En attente de connexions...") #

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) #
    try: #
        context.load_cert_chain(CERT_FILE, KEY_FILE) #
    except FileNotFoundError: #
        logging.error(f"Erreur: Le fichier de certificat '{CERT_FILE}' ou la clé '{KEY_FILE}' est introuvable.") #
        logging.error("Assurez-vous qu'ils sont dans le même répertoire que le script ou que les chemins sont corrects.") #
        logging.error("Générez-les avec OpenSSL (voir instructions précédentes).") #
        return #
    except ssl.SSLError as e: #
        logging.error(f"Erreur SSL lors du chargement du certificat : {e}") #
        logging.error("Vérifiez la validité de votre certificat et de votre clé (phrase secrète si vous en avez mis une).") #
        return #

    try: #
        while True: #
            newsocket, fromaddr = bindsocket.accept() #
            logging.info(f"Nouvelle connexion TCP entrante de : {fromaddr}") #
            try: #
                connstream = context.wrap_socket(newsocket, server_side=True) #
                handle_client(connstream) #
            except ssl.SSLError as e: #
                logging.error(f"Erreur SSL lors du handshake client (probablement un problème de certificat ou de version TLS) : {e}") #
                newsocket.close() #
            except Exception as e: #
                logging.error(f"Erreur lors de l'établissement de la connexion SSL : {e}") #
                newsocket.close() #
    except KeyboardInterrupt: #
        logging.info("\nServeur TCP/SSL Backend arrêté.") #
    except Exception as e: #
        logging.error(f"Une erreur inattendue dans le serveur principal : {e}") #
    finally: #
        bindsocket.close() #

if __name__ == "__main__": #
    run_server() #