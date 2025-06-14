import http.server
import socketserver
import logging
import json

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

PORT = 50001
HOST = "127.0.0.1"

class NDAHandler(http.server.BaseHTTPRequestHandler):
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

        if self.path.startswith('/nda'):
            logging.info("C'est une requête pour l'acceptation de l'NDA. Envoi de la réponse mockée.")
            mock_response_data = {
                "jwt": "your_simulated_jwt_token_for_nda_acceptance_12345ABCDEF_GHIKLMNO"
            }
            response_body = json.dumps(mock_response_data).encode('utf-8')

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Content-Length', str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)
            logging.info("Réponse NDA mockée envoyée.")
        else:
            logging.warning(f"Endpoint POST non géré sur le serveur NDA: {self.path}. Envoi d'une réponse par défaut.")
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Endpoint not found on NDA server.")
            
        logging.info("-" * 80)

    def do_GET(self):
        logging.info(f"Requête GET reçue sur : {self.path}")
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"OK from NDA Server.")
        logging.info("-" * 80)

with socketserver.TCPServer((HOST, PORT), NDAHandler) as httpd:
    logging.info(f"Serveur NDA démarré sur http://{HOST}:{PORT}")
    logging.info("LANCEZ LE JEU AVEC LE PARAMÈTRE : -steam_auth=\"http://127.0.0.1:50001\"")
    logging.info("Appuyez sur Ctrl+C pour arrêter ce serveur.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logging.info("\nServeur NDA arrêté.")
        httpd.shutdown()