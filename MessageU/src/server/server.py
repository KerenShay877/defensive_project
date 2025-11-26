"""
MessageU server configuration
Keren Shay
"""

import os
import sys
import socket
import struct
import threading
import base64
import hashlib

from data_storage import PersistenceGateway
from message_protocol import CommunicationEngine, MessageTypes

# Ensure server directory is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# Network configuration

class NetworkConfig:
    """Holds and loads server network settings."""
    def __init__(self, default_port: int = 1357):
        self.host = "0.0.0.0"
        self.port = default_port

    # Load port from file
    def load_port(self, filename: str = "myport.info") -> None:
        try:
            with open(filename, "r") as f:
                self.port = int(f.read().strip())
                print(f"Port loaded from {filename}: {self.port}")
        except FileNotFoundError:
            print(f"{filename} not found, using default port {self.port}")
        except (ValueError, OSError) as e:
            print(f"Error reading {filename}: {e}, using default port {self.port}")


# Socket management

class SocketServer:
    """Wraps the server socket lifecycle."""
    def __init__(self, config: NetworkConfig):
        self.cfg = config
        self.sock = None

    # Start the server
    def start(self) -> bool:
        print("Starting server...")
        self.cfg.load_port()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind((self.cfg.host, self.cfg.port))
            self.sock.listen(5)
            print(f"Listening on {self.cfg.host}:{self.cfg.port}")
            return True
        except socket.error as e:
            print(f"Bind failed: {e}")
            return False

    def accept(self):
        return self.sock.accept()

    def close(self):
        if self.sock:
            self.sock.close()


# Protocol handling

class ProtocolHandler:
    """Routes incoming protocol codes to the correct logic."""
    def __init__(self, storage: PersistenceGateway, comms: CommunicationEngine):
        self.db = storage
        self.comms = comms

    def _fail(self, msg: str) -> bytes:
        return self.comms.build_failure_reply(msg)

    # Add user to DB
    def register(self, payload: bytes) -> bytes:
        if len(payload) < 1279:
            return self._fail("Invalid registration payload")
        username = payload[:255].rstrip(b"\0").decode("utf-8", "replace")
        pubkey = payload[255:1279].rstrip(b"\0").decode("utf-8", "replace")
        cid = hashlib.md5(f"{username}{pubkey}".encode()).hexdigest()[:16]
        if self.db.add_account(cid, username, pubkey):
            print(f"Registered {username} ({cid})")
            return self.comms.build_register_reply(True, cid, "Registration successful!")
        return self.comms.build_register_reply(False, "", "Client already exists in database")

    def login(self, payload: bytes) -> bytes:
        return self._fail("Login not implemented yet")

    def send_message(self, payload: bytes) -> bytes:
        if len(payload) < 275:
            return self._fail("Invalid send message payload")
        sender_id = payload[:16].rstrip(b"\0").decode("utf-8")
        recipient = payload[16:271].rstrip(b"\0").decode("utf-8")
        if not recipient:
            return self._fail("Empty recipient")
        msg_len = int.from_bytes(payload[271:275], "little")
        if len(payload) < 275 + msg_len:
            return self._fail("Invalid message content length")
        content_b64 = base64.b64encode(payload[275:275 + msg_len]).decode("ascii")
        rec_client = self.db.resolve_account(recipient)
        if not rec_client:
            return self.comms.build_message_send_reply(False, f"Recipient '{recipient}' not found")
        if self.db.persist_message(sender_id, rec_client["client_id"], 1, content_b64):
            return self.comms.build_message_send_reply(True, f"Message sent successfully to {rec_client['name']}")
        return self.comms.build_message_send_reply(False, "Failed to store message")

    def get_messages(self, payload: bytes) -> bytes:
        if len(payload) < 16:
            return self._fail("Invalid waiting messages request")
        cid = payload[:16].rstrip(b"\0").decode("utf-8")
        msgs = self.db.fetch_pending_messages(cid)
        if msgs:
            self.db.purge_messages([m["id"] for m in msgs])
        return self.comms.build_message_list_reply(msgs)

    def list_users(self, payload: bytes) -> bytes:
        return self.comms.build_user_list_reply(self.db.list_accounts())

    def get_public_key(self, payload: bytes) -> bytes:
        if len(payload) < 255:
            return self._fail("Invalid public key request payload")
        ident = payload[:255].rstrip(b"\0").decode("utf-8")
        if not ident:
            return self._fail("Empty client identifier")
        client = self.db.resolve_account(ident)
        if client:
            return self.comms.build_key_reply(True, client["client_id"], client["public_key"], f"Public key for {client['name']}")
        return self.comms.build_key_reply(False, "", "", f"Client '{ident}' not found")

    def send_symmetric_key(self, payload: bytes) -> bytes:
        if len(payload) < 275:
            return self._fail("Invalid symmetric key request payload")
        sender_id = payload[:16].rstrip(b"\0").decode("utf-8")
        recipient = payload[16:271].rstrip(b"\0").decode("utf-8")
        if not recipient:
            return self._fail("Empty recipient")
        key_len = int.from_bytes(payload[271:275], "little")
        if len(payload) < 275 + key_len:
            return self._fail("Invalid encrypted key length")
        rec_client = self.db.resolve_account(recipient)
        if not rec_client:
            return self._fail(f"Recipient '{recipient}' not found")
        key_b64 = base64.b64encode(payload[275:275 + key_len]).decode("ascii")
        if self.db.persist_message(sender_id, rec_client["client_id"], 2, key_b64):
            return self.comms.encode_outgoing(MessageTypes.SYM_KEY_OK, b"Symmetric key received")
        return self._fail("Failed to store symmetric key")

    def logout(self, payload: bytes) -> bytes:
        return self._fail("Logout not implemented yet")

    def route(self, code: int, payload: bytes, addr: tuple) -> bytes:
        routes = {
            1000: self.register,
            2000: self.login,
            3000: self.send_message,
            4000: self.get_messages,
            5000: self.list_users,
            5002: self.get_public_key,
            5004: self.send_symmetric_key,
            6000: self.logout
        }
        handler = routes.get(code)
        if not handler:
            return self._fail("Unknown protocol code")
        return handler(payload)


# Client connection handler

class ClientSession:
    """Handles a single client connection."""
    def __init__(self, sock: socket.socket, addr: tuple, processor: ProtocolHandler, active_flag: threading.Event):
        self.sock = sock
        self.addr = addr
        self.proc = processor
        self.active_flag = active_flag

    def run(self):
        print(f"Connected: {self.addr}")
        try:
            while self.active_flag.is_set():
                header = self._recv_exact(9)
                if not header:
                    break
                _, code, size, _ = struct.unpack("<BHHI", header)
                payload = self._recv_exact(size)
                if payload is None:
                    break
                full = header + payload
                code, payload = self.proc.comms.decode_incoming(full)
                if not code:
                    continue
                resp = self.proc.route(code, payload, self.addr)
                if resp:
                    self.sock.sendall(resp)
        except socket.error as e:
            print(f"Socket error {self.addr}: {e}")
        finally:
            self.close()

    def _recv_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

# Main server

class Server:
    """Main server defentions"""
    def __init__(self):
        self.cfg = NetworkConfig()
        self.sock_mgr = SocketServer(self.cfg)
        self.db = PersistenceGateway()
        self.comms = CommunicationEngine()
        self.proc = ProtocolHandler(self.db, self.comms)
        self.active_flag = threading.Event()

    def start(self):
        if not self.sock_mgr.start():
            return
        self.active_flag.set()
        print("Server ready for connections.")
        try:
            while self.active_flag.is_set():
                client_sock, client_addr = self.sock_mgr.accept()
                print(f"New connection from {client_addr}")
                session = ClientSession(client_sock, client_addr, self.proc, self.active_flag)
                t = threading.Thread(target=self._handle_client, args=(session,), daemon=True)
                t.start()
        except KeyboardInterrupt:
            print("\nShutdown signal received.")
        finally:
            self.stop()

    def _handle_client(self, session: ClientSession):
        try:
            session.run()
        except Exception as e:
            print(f"Error in client session {session.addr}: {e}")
        finally:
            session.close()

    def stop(self):
        print("Stopping server...")
        self.active_flag.clear()
        self.sock_mgr.close()
        self.db.shutdown()
        print("Server stopped.")


def main():
    srv = Server()
    srv.start()


if __name__ == "__main__":
    main()
