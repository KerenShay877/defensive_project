"""
Database for MessageU
I use SQLite with thread connections
Keren Shay
"""

import sqlite3
import threading
import time
from typing import List, Dict, Any, Optional


# Connection and database structure

class ThreadLocalConnection:
    """Thread SQLite connection manager"""

    def __init__(self, db_file: str):
        self._db_file = db_file
        self._local = threading.local()

    @property
    def path(self) -> str:
        return self._db_file

    # Create connection with DB
    def connection(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            self._local.conn = sqlite3.connect(self._db_file) 
        return self._local.conn

    def cursor(self) -> sqlite3.Cursor:
        return self.connection().cursor() 

    # Close connection
    def close(self) -> None:
        if hasattr(self._local, "conn"): 
            self._local.conn.close()
            del self._local.conn
            print("Database connection closed")


class Schema:
    """Creates required tables if they don't exist"""

    # Method creates tables if they don't already exist
    @staticmethod
    def ensure(conn: sqlite3.Connection) -> None:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                public_key TEXT NOT NULL,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_client_id TEXT NOT NULL,
                to_client_id TEXT NOT NULL,
                message_type INTEGER NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (from_client_id) REFERENCES clients (client_id),
                FOREIGN KEY (to_client_id) REFERENCES clients (client_id)
            )
        """)
        conn.commit()
        print("Database schema checked!")


# Client operations

class ClientStore:
    """Methods for clients"""

    def __init__(self, conn_mgr: ThreadLocalConnection): # initialize database connection
        self._db = conn_mgr

    # Add client to DB
    def insert(self, cid: str, name: str, pubkey: str) -> bool:
        try:
            self._db.cursor().execute(
                "INSERT INTO clients (client_id, name, public_key) VALUES (?, ?, ?)",
                (cid, name, pubkey)
            ) 
            self._db.connection().commit()
            print(f"Client added: {name} ({cid})")
            return True
        except sqlite3.IntegrityError:
            print(f"Client already exists: {cid}")
            return False
        except sqlite3.Error as e:
            print(f"Error inserting client: {e}")
            return False

    # Get client from DB
    def get(self, cid: str) -> Optional[Dict[str, Any]]:
        try:
            cur = self._db.cursor()
            cur.execute("SELECT client_id, name, public_key, last_seen FROM clients WHERE client_id = ?", (cid,))
            row = cur.fetchone()
            return self._row_to_dict(row) if row else None
        except sqlite3.Error as e:
            print(f"Error fetching client: {e}")
            return None

    # Get a number of client from DB
    def get_all(self) -> List[Dict[str, Any]]:
        try:
            cur = self._db.cursor()
            cur.execute("SELECT client_id, name, public_key, last_seen FROM clients ORDER BY name")
            return [self._row_to_dict(r) for r in cur.fetchall()]
        except sqlite3.Error as e:
            print(f"Error listing clients: {e}")
            return []

    # Find a client in the DB
    def find(self, identifier: str) -> Optional[Dict[str, Any]]:
        try:
            cur = self._db.cursor()
            cur.execute(
                "SELECT client_id, name, public_key, last_seen FROM clients WHERE client_id = ? OR name = ?",
                (identifier, identifier)
            )
            row = cur.fetchone()
            return self._row_to_dict(row) if row else None
        except sqlite3.Error as e:
            print(f"Error finding client: {e}")
            return None

    # Update client latest activity time
    def heartbeat(self, cid: str) -> None:
        try:
            self._db.cursor().execute(
                "UPDATE clients SET last_seen = CURRENT_TIMESTAMP WHERE client_id = ?",
                (cid,)
            )
            self._db.connection().commit()
        except sqlite3.Error as e:
            print(f"Error updating heartbeat: {e}")

    @staticmethod
    def _row_to_dict(row: tuple) -> Dict[str, Any]:
        return {
            "client_id": row[0],
            "name": row[1],
            "public_key": row[2],
            "last_seen": row[3]
        }


# Message operations

class MessageStore:
    """Defenitions for messages"""

    def __init__(self, conn_mgr: ThreadLocalConnection):
        self._db = conn_mgr

    # Insert a message into the DB
    def insert(self, sender: str, recipient: str, mtype: int, content: str) -> bool:
        try:
            self._db.cursor().execute(
                "INSERT INTO messages (from_client_id, to_client_id, message_type, content) VALUES (?, ?, ?, ?)",
                (sender, recipient, mtype, content)
            )
            self._db.connection().commit()
            print(f"Message queued: {sender} -> {recipient}")
            return True
        except sqlite3.Error as e:
            print(f"Error storing message: {e}")
            return False

    # Grab all pending messages
    def pending_for(self, recipient: str) -> List[Dict[str, Any]]:
        try:
            cur = self._db.cursor()
            cur.execute("""
                SELECT m.id, m.from_client_id, m.to_client_id, m.message_type, m.content, m.created_at,
                       c.name as sender_name
                FROM messages m
                LEFT JOIN clients c ON m.from_client_id = c.client_id
                WHERE m.to_client_id = ?
                ORDER BY m.created_at ASC
            """, (recipient,))
            rows = cur.fetchall()
            return [
                {
                    "id": r[0],
                    "from_client_id": r[1],
                    "to_client_id": r[2],
                    "message_type": r[3],
                    "content": r[4],
                    "created_at": r[5],
                    "sender_name": r[6] or "Unknown"
                }
                for r in rows
            ]
        except sqlite3.Error as e:
            print(f"Error fetching pending messages: {e}")
            return []

    # Delete messages by ids
    def delete_by_ids(self, ids: List[int]) -> bool:
        if not ids:
            return True
        placeholders = ",".join("?" for _ in ids)
        for attempt in range(3):
            try:
                self._db.cursor().execute(f"DELETE FROM messages WHERE id IN ({placeholders})", ids)
                self._db.connection().commit()
                print(f"Deleted {len(ids)} messages")
                return True
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e) and attempt < 2:
                    print(f"DB locked, retry {attempt+1}/3")
                    time.sleep(0.1)
                    continue
                print(f"Operational error deleting messages: {e}")
                return False
            except sqlite3.Error as e:
                print(f"Error deleting messages: {e}")
                return False
        return False


# Database API

class PersistenceGateway:
    """Database API"""

    def __init__(self, path: str = "defensive.db"):
        self._conn_mgr = ThreadLocalConnection(path)
        self.clients = ClientStore(self._conn_mgr)
        self.messages = MessageStore(self._conn_mgr)
        self._init_db()

    # Initalize the DB
    def _init_db(self) -> None:
        try:
            conn = sqlite3.connect(self._conn_mgr.path)
            Schema.ensure(conn)
            conn.close()
            print(f"Database ready: {self._conn_mgr.path}")
        except sqlite3.Error as e:
            print(f"Failed to initialize DB: {e}")
            raise

    # Client methods
    def add_account(self, uid: str, name: str, pubkey: str) -> bool:
        return self.clients.insert(uid, name, pubkey)

    def fetch_account(self, uid: str) -> Optional[Dict[str, Any]]:
        return self.clients.get(uid)

    def list_accounts(self) -> List[Dict[str, Any]]:
        return self.clients.get_all()

    def resolve_account(self, identifier: str) -> Optional[Dict[str, Any]]:
        return self.clients.find(identifier)

    def touch_heartbeat(self, uid: str) -> None:
        self.clients.heartbeat(uid)

    def persist_message(self, sender: str, recipient: str, mtype: int, body: str) -> bool:
        return self.messages.insert(sender, recipient, mtype, body)

    def fetch_pending_messages(self, recipient: str) -> List[Dict[str, Any]]:
        return self.messages.pending_for(recipient)

    def purge_messages(self, ids: List[int]) -> bool:
        return self.messages.delete_by_ids(ids)

    register_client = add_account
    get_client = fetch_account
    get_all_clients = list_accounts
    get_client_by_identifier = resolve_account
    get_waiting_messages = fetch_pending_messages
    delete_messages = purge_messages
    store_message = persist_message
    update_last_seen = touch_heartbeat
