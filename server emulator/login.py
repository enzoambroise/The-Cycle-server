import http.server
import socketserver
import logging
import json

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

PORT = 50002
HOST = "127.0.0.1"

class LoginHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        logging.info(format % args)

    def do_POST(self):
        logging.info(f"Requête POST reçue sur : {self.path}")
        logging.info("En-têtes de la requête :")
        for header, value in self.headers.items():
            logging.info(f"  {header}: {value}")

        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 0:
            post_data = self.rfile.read(content_length)
            logging.info("Corps de la requête (octets bruts) :")
            logging.info(post_data)
            try:
                decoded_data = post_data.decode('utf-8')
                logging.info("Corps de la requête (décodé en UTF-8) :")
                logging.info(decoded_data)
            except UnicodeDecodeError:
                logging.warning("Le corps de la requête n'est pas décodable en UTF-8.")
        else:
            logging.info("Aucun corps dans la requête POST.")

        if self.path.startswith('/login'):
            logging.info("C'est une requête pour le login. Envoi de la réponse mockée.")
            mock_response_data = {
                "success": True,
                "userId": "76561198000000001",
                "userName": "PlayerOfTheCycle",
                "authToken": "FAKE_AUTH_TOKEN_FROM_YOUR_SERVER_LONG_STRING_FOR_LOGIN",
                "isNewUser": False,
                "acceptedNDA": True,
                "country": "FR"
            }
            response_body = json.dumps(mock_response_data).encode('utf-8')

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Content-Length', str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)
            logging.info("Réponse Login mockée envoyée.")
        else:
            logging.warning(f"Endpoint POST non géré sur le serveur de login: {self.path}. Envoi d'une réponse par défaut.")
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Endpoint not found on login server.")
            
        logging.info("-" * 80)

    def do_GET(self):
        logging.info(f"Requête GET reçue sur : {self.path}")
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"OK from Login Server.")
        logging.info("-" * 80)

with socketserver.TCPServer((HOST, PORT), LoginHandler) as httpd:
    logging.info(f"Serveur Login démarré sur http://{HOST}:{PORT}")
    logging.info("LANCEZ LE JEU AVEC LE PARAMÈTRE : -auth=\"http://127.0.0.1:50002\"")
    logging.info("Appuyez sur Ctrl+C pour arrêter ce serveur.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logging.info("\nServeur Login arrêté.")
        httpd.shutdown()