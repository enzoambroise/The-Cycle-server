import http.server
import socketserver
import logging
import json

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

PORT = 40003
HOST = "127.0.0.1"

class AnalyticsHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        logging.info(format % args)

    def do_POST(self):
        logging.info(f"Requête POST reçue sur le serveur Analytics: {self.path}")
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 0:
            post_data = self.rfile.read(content_length)
            try:
                decoded_data = post_data.decode('utf-8')
                logging.info(f"Corps de la requête Analytics (décodé en UTF-8) : {decoded_data}")
            except UnicodeDecodeError:
                logging.warning("Le corps de la requête Analytics n'est pas décodable en UTF-8.")
        else:
            logging.info("Aucun corps dans la requête POST Analytics.")

        # Réponse simple 200 OK pour l'analytics
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        response_body = json.dumps({"status": "ok"}).encode('utf-8') # Une réponse JSON simple
        self.send_header('Content-Length', str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)
        logging.info("Réponse Analytics mockée envoyée (200 OK).")
        logging.info("-" * 80)

    def do_GET(self):
        logging.info(f"Requête GET reçue sur le serveur Analytics: {self.path}")
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"OK from Analytics Server.")
        logging.info("Réponse Analytics mockée envoyée (200 OK).")
        logging.info("-" * 80)

with socketserver.TCPServer((HOST, PORT), AnalyticsHandler) as httpd:
    logging.info(f"Serveur Analytics démarré sur http://{HOST}:{PORT}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logging.info("\nServeur Analytics arrêté.")
    except Exception as e:
        logging.error(f"Une erreur inattendue dans le serveur Analytics : {e}")