import http.server
import socketserver
import threading
import logging
import json
import base64
from urllib.parse import urlparse, parse_qs

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

HOST = "127.0.0.1"
PORT_STEAM = 50001
PORT_AUTH = 50002


def decode_basic_auth_from_headers(headers):
    auth = headers.get('Authorization', '')
    if not auth or not auth.startswith('Basic '):
        return None, None
    try:
        b64 = auth.split(' ', 1)[1]
        decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
        if ':' in decoded:
            user, pwd = decoded.split(':', 1)
            return user, pwd
        return decoded, ''
    except Exception:
        return None, None


# -------------------------------------------------
# HANDLER POUR LE SERVEUR D'AUTHENTIFICATION STEAM
# -------------------------------------------------
class SteamAuthHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        logging.info(format % args)

    def do_POST(self):
        logging.info(f"[STEAM AUTH] POST → {self.path}")
        for header, value in self.headers.items():
            logging.info(f"  {header}: {value}")

        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b''
        logging.info(f"[STEAM AUTH] Corps brut ({len(post_data)} octets): {post_data}")

        # parser la query string (ex: /nda?steamTicket=...)
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        if qs:
            logging.info(f"[STEAM AUTH] Query string: {qs}")

        # Tentative de décodage UTF-8
        try:
            body_text = post_data.decode('utf-8')
            logging.info(f"[STEAM AUTH] Corps décodé : {body_text}")
            try:
                data = json.loads(body_text) if body_text else {}
                logging.info(f"[STEAM AUTH] JSON décodé : {data}")
            except json.JSONDecodeError:
                data = {}
        except UnicodeDecodeError:
            logging.warning("[STEAM AUTH] Impossible de décoder en UTF-8.")
            data = {}

        # Si c'est /nda envoyé au serveur steam (souvent le cas), on renvoie la structure NDA attendue
        if parsed.path.startswith("/nda"):
            logging.info("[STEAM AUTH] → Requête NDA (Steam) détectée.")
            mock_response = {
                "result": "OK",
                "nda": True,
                "jwt": "fake_steam_nda_jwt_1234567890"
            }
        else:
            # Réponse simulée de succès Steam générique
            mock_response = {
                "result": "OK",
                "jwt": "fake_steam_auth_token_ABCDE12345",
                "user_id": "steam_2002",
                "username": "SteamUser"
            }

        response_body = json.dumps(mock_response).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)
        logging.info("[STEAM AUTH] Réponse envoyée avec succès.\n" + "-" * 80)


# -------------------------------------------------
# HANDLER POUR LE SERVEUR NORMAL (NDA, LOGIN, REGISTER, RESET, ETC.)
# -------------------------------------------------
class AuthHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        logging.info(format % args)

    def do_POST(self):
        logging.info(f"[AUTH] POST → {self.path}")
        for header, value in self.headers.items():
            logging.info(f"  {header}: {value}")

        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b''
        logging.info(f"[AUTH] Corps brut ({len(post_data)} octets): {post_data}")

        try:
            decoded = post_data.decode('utf-8')
            logging.info(f"[AUTH] Corps décodé : {decoded}")
            try:
                json_body = json.loads(decoded) if decoded else {}
            except json.JSONDecodeError:
                json_body = {}
        except UnicodeDecodeError:
            decoded = ""
            json_body = {}
            logging.warning("[AUTH] Corps non décodable en UTF-8.")

        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        if qs:
            logging.info(f"[AUTH] Query string: {qs}")

        # -------------------------
        # Route NDA (local) — si le jeu envoie ici
        # -------------------------
        if path.startswith("/nda"):
            logging.info("[AUTH] → Requête NDA détectée.")
            # Récupération du steamTicket si fourni
            steam_ticket = qs.get("steamTicket", [""])[0] if qs else ""
            logging.info(f"[AUTH] steamTicket (début): {steam_ticket[:80]}...")
            mock_response = {
                "result": "OK",
                "nda": True,
                "jwt": "your_simulated_jwt_token_for_nda_acceptance_12345ABCDEF_GHIKLMNO"
            }

        # -------------------------
        # Route LOGIN
        # -------------------------
        elif path.startswith("/login"):
            logging.info("[AUTH] → Requête LOGIN détectée.")
            user, pwd = decode_basic_auth_from_headers(self.headers)
            logging.info(f"[AUTH] Authorization décodée: {user}:{pwd}")
            mock_response = {
                "result": "OK",
                "jwt_token": "fake_login_jwt_token_XYZ987",
                "user_id": "user_1001",
                "username": user or "TestUser"
            }

        # -------------------------
        # Route REGISTER
        # -------------------------
        elif path.startswith("/register"):
            logging.info("[AUTH] → Requête REGISTER détectée.")
            user, pwd = decode_basic_auth_from_headers(self.headers)
            logging.info(f"[AUTH] Authorization décodée: {user}:{pwd}")
            # On peut étendre ici pour stocker dans un fichier si besoin
            mock_response = {
                "result": "OK",
                "success": True,
                "message": f"User '{user or 'unknown'}' registered successfully.",
                "user_id": "user_registered_1002"
            }

        # -------------------------
        # Route RESET (réinitialisation mot de passe)
        # -------------------------
        elif path.startswith("/reset"):
            logging.info("[AUTH] → Requête RESET PASSWORD détectée.")
            user, _ = decode_basic_auth_from_headers(self.headers)
            logging.info(f"[AUTH] Compte concerné : {user}")
            # Si le jeu attend un champ précis, on peut l'ajouter.
            mock_response = {
                "result": "OK",
                "success": True,
                "message": f"Password reset request for '{user or 'unknown'}' processed."
            }

        # -------------------------
        # Autres routes non reconnues
        # -------------------------
        else:
            logging.warning(f"[AUTH] Endpoint non reconnu : {self.path}")
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Endpoint not found on AUTH server.")
            logging.info("-" * 80)
            return

        # Envoi de la réponse JSON
        response_body = json.dumps(mock_response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)
        logging.info("[AUTH] Réponse envoyée avec succès.\n" + "-" * 80)

    def do_GET(self):
        logging.info(f"[AUTH] GET → {self.path}")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK from AUTH Server.")
        logging.info("-" * 80)


# -------------------------------------------------
# FONCTIONS DE LANCEMENT
# -------------------------------------------------
def run_server(handler, host, port, name):
    with socketserver.TCPServer((host, port), handler) as httpd:
        logging.info(f"{name} démarré sur http://{host}:{port}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logging.info(f"\n{name} arrêté.")
            httpd.shutdown()

# -------------------------------------------------

if __name__ == "__main__":
    logging.info("=== SERVEURS D'AUTHENTIFICATION ===")
    logging.info(f"Lancez le jeu avec : -steam_auth=\"http://127.0.0.1:{PORT_STEAM}\"")
    logging.info(f"Le serveur NDA tourne sur : http://127.0.0.1:{PORT_AUTH}")
    logging.info("===================================")

    # Deux threads : SteamAuth + NDA/Auth
    threading.Thread(target=run_server, args=(SteamAuthHandler, HOST, PORT_STEAM, "SteamAuthServer"), daemon=True).start()
    run_server(AuthHandler, HOST, PORT_AUTH, "AuthServer")
