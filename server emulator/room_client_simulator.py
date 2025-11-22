import socket
import logging
import subprocess
import re
import psutil
from google.protobuf.any_pb2 import Any
from room_connect_pb2 import Connect as RoomConnectMessage

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

HOST = '127.0.0.1'
GAME_PROCESS_NAME = "Prospect-Win64-Shipping.exe"

def find_game_pid_by_name(process_name):
    logging.info(f"Recherche du PID pour le processus: '{process_name}'...")
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == process_name:
            logging.info(f"Processus '{process_name}' trouvé avec le PID {proc.info['pid']}")
            return proc.info['pid']
    logging.warning(f"Processus '{process_name}' non trouvé.")
    return None

def find_game_listening_tcp_port(game_pid):
    try:
        # Utilise 'netstat -ano' pour lister les connexions et les ports d'écoute avec les PIDs
        # Encodage 'cp850' pour Windows pour éviter les erreurs de décodage avec la sortie de netstat
        result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True, check=True, encoding='cp850')
        lines = result.stdout.splitlines()

        # Regex pour trouver une ligne TCP avec l'adresse locale 127.0.0.1, un port en écoute (0.0.0.0:0), et le PID du jeu
        pattern = re.compile(r"TCP\s+127\.0\.0\.1:(\d+)\s+0\.0\.0\.0:0\s+LISTENING\s+" + str(game_pid))

        for line in lines:
            match = pattern.search(line)
            if match:
                port = int(match.group(1))
                logging.info(f"Port TCP d'écoute du jeu trouvé : {port}")
                return port
        logging.warning(f"Aucun port TCP d'écoute trouvé pour le PID {game_pid}.")
        return None
    except Exception as e:
        logging.error(f"Erreur lors de la recherche du port TCP d'écoute: {e}")
        return None

def attempt_room_connect_http_post(host, port, room_id, address, current_path):
    """
    Tente d'envoyer un message room.Connect au serveur interne du jeu via HTTP POST.
    Retourne True si une réponse 200 OK est reçue, False sinon.
    """
    sock = None
    try:
        game_pid = find_game_pid_by_name(GAME_PROCESS_NAME)
        if not game_pid:
            logging.error(f"Le processus du jeu '{GAME_PROCESS_NAME}' n'est pas en cours d'exécution.")
            return False # Indique un échec

        dynamic_port = find_game_listening_tcp_port(game_pid)
        if not dynamic_port:
            logging.error("Impossible de trouver le port d'écoute du jeu. Assurez-vous que le jeu est lancé et initialise son port.")
            return False # Indique un échec

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5) # Timeout pour l'opération de socket
        logging.info(f"Tentative de connexion à {host}:{dynamic_port} (port TCP dynamique) via le PID {game_pid}...")
        sock.connect((host, dynamic_port))
        logging.info(f"Connexion TCP simple établie avec le jeu sur {host}:{dynamic_port}")

        # 1. Créer le message room.Connect
        room_connect_msg = RoomConnectMessage(roomId=room_id, addr=address)

        # 2. Encapsuler dans un message google.protobuf.Any
        any_message = Any()
        any_message.Pack(room_connect_msg) # 'Pack' sérialise le message et le stocke dans 'Any'

        # 3. Sérialiser le message Any
        serialized_any = any_message.SerializeToString()

        # 4. Construire la requête HTTP POST
        # Le chemin (path) est maintenant un paramètre de la fonction
        path_to_use = current_path
        content_type = "application/x-protobuf" # Type de contenu standard pour Protobuf binaire
        # Alternative si le jeu attend du Protobuf JSON: "application/json" et serialized_any = MessageToJson(any_message).encode('utf-8')

        request_body = serialized_any

        http_request = (
            f"POST {path_to_use} HTTP/1.1\r\n"
            f"Host: {host}:{dynamic_port}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(request_body)}\r\n"
            f"User-Agent: X-UnrealEngine-Agent\r\n" # Utilise le même User-Agent que pour le login/NDA
            f"Accept: */*\r\n" # Indique que le client accepte n'importe quel type de réponse
            f"\r\n" # Ligne vide pour séparer les en-têtes du corps
        ).encode('utf-8') + request_body # Le corps doit être des octets

        logging.info(f"Tentative d'envoi d'un message Protobuf (room.Connect) via HTTP POST au chemin '{path_to_use}'...")
        sock.sendall(http_request)
        logging.info(f"Requête HTTP POST de type '{any_message.type_url}' envoyée. Taille du corps: {len(request_body)} octets.")

        logging.info("Attente de la réponse du jeu...")
        response_data = b""
        while True:
            chunk = sock.recv(4096) # Lit les données par morceaux
            if not chunk:
                break # Fin de la connexion ou pas plus de données
            response_data += chunk
            # Simple détection de la fin des en-têtes HTTP (double CRLF)
            if b"\r\n\r\n" in response_data:
                # Dans un cas réel, il faudrait lire Content-Length pour s'assurer d'avoir tout le corps.
                # Pour les messages d'erreur 404/501, le corps est petit, donc c'est suffisant.
                break

        if response_data:
            logging.info(f"Réponse HTTP complète reçue. Taille: {len(response_data)} octets.")
            decoded_response = response_data.decode('utf-8', errors='ignore')
            logging.info("Données brutes décodées (UTF-8, ignorées erreurs):\n" + decoded_response)

            if "HTTP/1.1 200 OK" in decoded_response:
                logging.info(f"SUCCÈS : La requête HTTP POST au chemin '{path_to_use}' a été acceptée par le serveur interne du jeu.")
                return True # Indique le succès
            elif "HTTP/1.1 400 Bad Request" in decoded_response:
                logging.error(f"ÉCHEC : Le serveur interne du jeu a renvoyé un '400 Bad Request' pour le chemin '{path_to_use}'. Le format de la requête (en-têtes, Content-Type, ou corps) est probablement incorrect pour ce chemin ou le contenu n'est pas valide.")
            elif "HTTP/1.1 404 Not Found" in decoded_response:
                logging.error(f"ÉCHEC : Le serveur interne du jeu a renvoyé un '404 Not Found' pour le chemin '{path_to_use}'. Le chemin (path) de l'URL est probablement incorrect.")
            else:
                logging.warning(f"AVERTISSEMENT : Réponse inattendue du jeu pour le chemin '{path_to_use}'. Première ligne: {decoded_response.splitlines()[0]}")
        else:
            logging.warning(f"Aucune réponse reçue du jeu pour le chemin '{path_to_use}'.")

    except socket.timeout:
        logging.error(f"Délai de connexion/communication dépassé pour le chemin '{path_to_use}'.")
    except ConnectionRefusedError:
        logging.error(f"Connexion refusée pour le chemin '{path_to_use}'. Assurez-vous que le jeu tourne et écoute bien sur le port trouvé.")
    except Exception as e:
        logging.error(f"Une erreur inattendue est survenue pour le chemin '{path_to_use}': {e}")
    finally:
        if sock:
            sock.close()
            logging.info("Connexion TCP fermée.")
    return False # Indique l'échec

if __name__ == "__main__":
    # Liste des chemins d'URL à tester
    candidate_paths = [
        "/",
        "/connect",
        "/lobby",
        "/room",
        "/api",
        "/api/connect",
        "/api/lobby",
        "/api/room",
        "/action",
        "/command",
        "/player/connect", # Ajouté quelques chemins communs
        "/game/connect",
        "/session",
        "/message",
        # Ajoutez d'autres chemins si vous avez des idées basées sur des conventions d'API ou d'autres analyses.
    ]

    found_successful_path = False
    logging.info("--- Début des tests de chemins pour le serveur interne du jeu ---")
    for path_to_try in candidate_paths:
        logging.info(f"\n--- Tentative avec le chemin : {path_to_try} ---")
        if attempt_room_connect_http_post(HOST, 0, "lobby_map_id_123", "127.0.0.1:7777", path_to_try):
            found_successful_path = True
            break # Arrête dès qu'un chemin fonctionne
        logging.info(f"Chemin '{path_to_try}' échoué. Passage au suivant.")

    if not found_successful_path:
        logging.error("\nToutes les tentatives de chemins ont échoué. Le chemin correct ou le format de la requête (Content-Type/corps) reste inconnu pour une réponse 200 OK.")
    else:
        logging.info("\nUn chemin de requête HTTP POST correct a été trouvé. Vous pouvez maintenant affiner votre message Protobuf ou votre logique de réponse du jeu.")