import socket
import ssl
import logging
import json
from google.protobuf.any_pb2 import Any
from login_response_pb2 import LoginResponse, LoginResponse_Result

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

PORT = 50051
HOST = "127.0.0.1"

CERT_FILE = 'server.crt'
KEY_FILE = 'server.key'

PROTOCOL_HEADER_LENGTH = 4 

def handle_protobuf_message(data):
    decoded_info = {"message_type": "Inconnu", "details": "Impossible de décoder"}
    
    protobuf_payload = data[PROTOCOL_HEADER_LENGTH:]

    any_message = Any()
    try:
        any_message.ParseFromString(protobuf_payload)
        logging.info(f"DEBUG: Any message type_url reçu : '{any_message.type_url}'")
        decoded_info["message_type"] = any_message.type_url

        if any_message.type_url == "type.googleapis.com/LoginRequest":
            logging.info(f"DEBUG: Message de type 'LoginRequest' identifié.")
            decoded_info["details"] = "Message LoginRequest reçu. Contenu décodé ci-dessous si disponible."
            
            try:
                jwt_start_marker = b"your_simulated_jwt_token"
                jwt_start_index = protobuf_payload.find(jwt_start_marker)
                if jwt_start_index != -1:
                    decoded_info["JWT Token"] = protobuf_payload[jwt_start_index : jwt_start_index + len(jwt_start_marker) + 30].decode('utf-8', errors='ignore') + "..."

                client_version_marker = b"PROSPECT/Releases/"
                version_start_index = protobuf_payload.find(client_version_marker)
                if version_start_index != -1:
                    version_full_start = protobuf_payload.rfind(b'\x12', 0, version_start_index)
                    if version_full_start == -1: # Fallback if rfind doesn't work for some reason
                        version_full_start = 0
                    version_end_index = protobuf_payload.find(b'\x00', version_full_start)
                    if version_end_index == -1:
                        version_end_index = len(protobuf_payload)
                    decoded_info["Client Version"] = protobuf_payload[version_full_start + 2 : version_end_index].decode('utf-8', errors='ignore').strip()
            except Exception as e:
                logging.warning(f"Impossible d'extraire les détails du LoginRequest des octets bruts : {e}")
        else:
            # Pour les autres types de messages, nous loggons la valeur brute pour l'analyse
            logging.info(f"DEBUG: Contenu brut du message (Any.value) pour {any_message.type_url}: {any_message.value.hex()}")


    except Exception as e:
        logging.error(f"Erreur lors du décodage du message Any ou Protobuf : {e}")
        logging.error(f"Payload Protobuf brut : {protobuf_payload.hex()}")
    
    return decoded_info

def create_login_response(session_id, username_val, user_id):
    """
    Crée un message LoginResponse simulé et l'enveloppe dans un google.protobuf.Any.
    """
    response = LoginResponse(
        result=LoginResponse_Result.OK,
        session_id=session_id,
        username=username_val,
        user_id=user_id,
    )

    simulated_jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxrwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    response.jwt_token = simulated_jwt_token

    any_response = Any()
    any_response.Pack(response)
    return any_response

def handle_client(connstream):
    logging.info("Gestion d'une nouvelle connexion client SSL...")
    try:
        while True:
            # First, try to receive the header
            header_bytes = connstream.recv(PROTOCOL_HEADER_LENGTH)
            if not header_bytes:
                logging.info("Client déconnecté (en-tête vide).")
                break # Client closed the connection

            if len(header_bytes) < PROTOCOL_HEADER_LENGTH:
                logging.warning(f"En-tête incomplet reçu ({len(header_bytes)} octets). Fermeture de la connexion.")
                break # Incomplete header, close connection

            # Then, receive the rest of the data
            data = connstream.recv(4096) # Read up to 4096 bytes of the payload
            if not data:
                logging.info("Client déconnecté (aucune donnée reçue après l'en-tête).")
                break # Client closed connection after header

            full_message_data = header_bytes + data
            
            logging.info(f"Données brutes reçues (y compris l'en-tête {header_bytes.hex()}) ({len(full_message_data)} octets): {full_message_data.hex()}")

            decoded_request_info = handle_protobuf_message(full_message_data)
            logging.info("Requête Protobuf décodée :")
            for key, value in decoded_request_info.items():
                logging.info(f"    {key}: {value}")

            if decoded_request_info.get("message_type") == "type.googleapis.com/LoginRequest":
                session_id = "some_generated_session_id_123"
                username_val = "Player123"
                user_id = "user_abc_456"
                any_response = create_login_response(session_id, username_val, user_id)
                serialized_response = any_response.SerializeToString()
                
                response_with_header = b'\x91\x00\x00\x00' + serialized_response

                logging.info(f"Message Protobuf sérialisé (Any(LoginResponse)) ({len(serialized_response)} octets): {serialized_response.hex()}")
                logging.info(f"Réponse complète à envoyer ({len(response_with_header)} octets): {response_with_header.hex()}")
                connstream.sendall(response_with_header)
                logging.info("Réponse de login Protobuf envoyée.")
                # Nous ne mettons PAS de 'break' ici. La boucle continue d'écouter les messages suivants.
            else:
                logging.warning(f"Type de message Protobuf non géré : {decoded_request_info.get('message_type')}. Aucune réponse automatique envoyée.")
                # Nous ne mettons PAS de 'break' ici. La boucle continue d'écouter les messages suivants.

    except ssl.SSLError as e:
        logging.error(f"Erreur SSL lors de la communication client : {e}")
    except socket.error as e:
        logging.error(f"Erreur de socket lors de la communication client : {e}")
    except Exception as e:
        logging.error(f"Erreur inattendue lors de la gestion du client : {e}")
    finally:
        logging.info("Connexion SSL fermée.")
        connstream.close()

def run_server():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    context.options |= ssl.OP_NO_TLSv1_3

    bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bindsocket.bind((HOST, PORT))
    bindsocket.listen(5)

    logging.info(f"Serveur TCP/SSL Backend démarré sur {HOST}:{PORT}")
    logging.info(f"Certificat : {CERT_FILE}, Clé : {KEY_FILE}")

    try:
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
    except KeyboardInterrupt:
        logging.info("\nServeur TCP/SSL Backend arrêté.")
    except FileNotFoundError:
        logging.error(f"Erreur : Le certificat '{CERT_FILE}' ou la clé '{KEY_FILE}' est introuvable.")
        logging.error("Assurez-vous qu'ils sont dans le même répertoire que le script ou que les chemins sont corrects.")
        logging.error("Générez-les avec OpenSSL (voir instructions précédentes).")
        return
    except ssl.SSLError as e:
        logging.error(f"Erreur SSL lors du chargement du certificat : {e}")
        logging.error("Vérifiez la validité de votre certificat et de votre clé (phrase secrète si vous en avez mis une).")
        return
    except Exception as e:
        logging.error(f"Une erreur inattendue dans le serveur principal : {e}")
    finally:
        bindsocket.close()

if __name__ == "__main__":
    run_server()