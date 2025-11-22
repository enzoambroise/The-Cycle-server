import socket
import ssl
import logging
import time
import binascii
from google.protobuf.any_pb2 import Any
from room_connect_pb2 import Connect as RoomConnect
from login_response_pb2 import LoginResponse

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

HOST = "127.0.0.1"
PORT = 50051

def hexdump(b: bytes, maxlen=200):
    s = binascii.hexlify(b[:maxlen]).decode()
    return ' '.join(s[i:i+2] for i in range(0, len(s), 2)) + ((" ... (%d bytes)" % (len(b)-maxlen)) if len(b) > maxlen else "")

# Construire message RoomConnect
rc = RoomConnect()
rc.addr = "127.0.0.1:7777"
rc.roomId = "test_room_001"

a = Any()
a.Pack(rc)
payload = a.SerializeToString()

header = b'\x91\x00\x00\x00'  # même en-tête observé côté serveurs
to_send = header + payload

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

logging.info(f"Connexion à {HOST}:{PORT} ...")
with socket.create_connection((HOST, PORT)) as sock:
    with context.wrap_socket(sock, server_hostname=HOST) as ssock:
        logging.info(f"Connecté. Envoi du RoomConnect ({len(to_send)} bytes).")
        ssock.sendall(to_send)

        # attendre une éventuelle réponse
        time.sleep(0.2)
        try:
            resp = ssock.recv(8192)
            if not resp:
                logging.info("Aucune réponse reçue (socket vide).")
            else:
                logging.info(f"Réponse reçue ({len(resp)} bytes) hexdump:\n{hexdump(resp,400)}")
                try:
                    # Strip the header if present (4 bytes 0x91 00 00 00)
                    if resp[:4] == b'\x91\x00\x00\x00':
                        resp_payload = resp[4:]
                    else:
                        resp_payload = resp
                    any_resp = Any()
                    any_resp.ParseFromString(resp_payload)
                    logging.info(f"Any.type_url = {any_resp.type_url}")
                    if any_resp.type_url.endswith("LoginResponse") or any_resp.type_url.endswith("/LoginResponse"):
                        lr = LoginResponse()
                        any_resp.Unpack(lr)
                        logging.info("LoginResponse unpacked:")
                        logging.info(f"  result: {lr.result}")
                        logging.info(f"  session_id: {lr.session_id}")
                        logging.info(f"  username: {lr.username}")
                        logging.info(f"  user_id: {lr.user_id}")
                except Exception:
                    logging.exception("Impossible de parser la réponse protobuf.")
        except Exception:
            logging.exception("Erreur lors de la lecture de la réponse.")
