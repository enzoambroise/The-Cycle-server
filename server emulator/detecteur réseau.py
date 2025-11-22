#!/usr/bin/env python3
"""
Serveur TCP+UDP qui reste en écoute en continu sur une plage de ports,
n'affiche **rien** sauf lorsqu'une connexion/paquet est détecté.
Exclut les ports listés dans EXCLUDE_PORTS.
"""

import asyncio
import socket
import sys

# CONFIG
EXCLUDE_PORTS = {25565, 50001,50002}           # ports à exclure
START_PORT = 1                    # début de la plage (1..65535)
END_PORT = 65535                  # fin de la plage
CONCURRENT_BINDS = 800            # nombre de binds simultanés (ajuster si besoin)
TCP_BACKLOG = 50                  # backlog pour les serveurs TCP
PRINT_HEX_BYTES = 64              # combien d'octets afficher du payload (pour debug)

# ---------- handlers ----------
async def handle_tcp_reader(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int):
    addr = writer.get_extra_info('peername')
    # Print on first connect only
    print(f"[DETECTED][TCP] connexion depuis {addr} -> port {port}")
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            # Si tu veux voir le contenu, décommenter la ligne ci-dessous.
            # On limite l'output au début du payload.
            snippet = data[:PRINT_HEX_BYTES]
            print(f"[DETECTED][TCP] données {len(data)} bytes depuis {addr} -> port {port}: {snippet!r}")
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

class UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, port):
        self.port = port

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        snippet = data[:PRINT_HEX_BYTES]
        print(f"[DETECTED][UDP] paquet {len(data)} bytes depuis {addr} -> port {self.port}: {snippet!r}")

# ---------- create servers ----------
async def try_bind_port(loop, port, sem):
    """Tente de binder TCP et UDP sur le port donné; silence si échec."""
    if port in EXCLUDE_PORTS:
        return None

    # We use semaphore to limit concurrent binds
    async with sem:
        tcp_server = None
        udp_transport = None
        try:
            # TCP server
            try:
                tcp_server = await asyncio.start_server(
                    lambda r, w: handle_tcp_reader(r, w, port),
                    host='0.0.0.0', port=port, backlog=TCP_BACKLOG
                )
            except Exception:
                tcp_server = None

            # UDP server
            try:
                udp_transport, _ = await loop.create_datagram_endpoint(
                    lambda: UDPProtocol(port),
                    local_addr=('0.0.0.0', port)
                )
            except Exception:
                udp_transport = None

            # If neither bound, return False
            if not tcp_server and not udp_transport:
                return None

            return (port, tcp_server, udp_transport)
        except Exception:
            # Silencie les erreurs de bind
            try:
                if udp_transport:
                    udp_transport.close()
            except Exception:
                pass
            try:
                if tcp_server:
                    tcp_server.close()
                    await tcp_server.wait_closed()
            except Exception:
                pass
            return None

async def main():
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(CONCURRENT_BINDS)

    bound_servers = []  # list of tuples (port, tcp_server, udp_transport)

    # Démarrage des binds par lots (pour éviter surcharger la machine)
    tasks = []
    for port in range(START_PORT, END_PORT + 1):
        if port in EXCLUDE_PORTS:
            continue
        tasks.append(asyncio.create_task(try_bind_port(loop, port, sem)))

        # Flush tasks périodiquement pour limiter la mémoire
        if len(tasks) >= CONCURRENT_BINDS:
            results = await asyncio.gather(*tasks)
            for r in results:
                if r:
                    bound_servers.append(r)
            tasks = []

    # Gather remaining tasks
    if tasks:
        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                bound_servers.append(r)

    # Affichage rapide du nombre de sockets réellement bindés (silencieux pendant l'écoute)
    bound_count = sum(1 for t in bound_servers if t is not None)
    # On n'imprime pas les ports individuellement (respect de ta consigne), mais on peut commenter la ligne ci-dessous si tu veux savoir.
    print(f"[INFO] {bound_count} sockets bindés (TCP et/ou UDP). Le script reste en écoute...")

    # Le script reste en écoute indéfiniment.
    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        pass
    finally:
        # Fermeture propre en cas d'arrêt
        for port, tcp_server, udp_transport in bound_servers:
            try:
                if tcp_server:
                    tcp_server.close()
                    await tcp_server.wait_closed()
            except Exception:
                pass
            try:
                if udp_transport:
                    udp_transport.close()
            except Exception:
                pass

if __name__ == "__main__":
    # Exécuter avec privilèges admin si tu veux binder <1024
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Arrêt demandé par l'utilisateur.")
        sys.exit(0)
