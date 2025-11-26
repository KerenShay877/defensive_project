"""
MessageU server message protocol
Keren Shay
"""

from __future__ import annotations

import io
import struct
from enum import IntEnum
from typing import Optional, Tuple, Dict, Any, List


class MessageTypes(IntEnum):
    REGISTER = 1000
    REGISTER_OK = 1001
    REGISTER_ERR = 1002
    AUTH = 2000
    AUTH_OK = 2001
    AUTH_ERR = 2002
    MSG_SEND = 3000
    MSG_SEND_OK = 3001
    MSG_SEND_ERR = 3002
    MSG_GET = 4000
    MSG_LIST = 4001
    USER_GET = 5000
    USER_LIST = 5001
    KEY_GET = 5002
    KEY_RETURN = 5003
    SYM_KEY = 5004
    SYM_KEY_OK = 5005
    DISCONNECT = 6000
    DISCONNECT_OK = 6001


# Utilitie functions needed for operations

_LE_U8_U16_U16_U32 = struct.Struct("<BHHI")
_LE_U32 = struct.Struct("<I")
_LE_U32U8U32 = struct.Struct("<IBI")


def _u8(x: int) -> bytes:
    return bytes((x & 0xFF,))


def _le_u32(x: int) -> bytes:
    return _LE_U32.pack(x & 0xFFFFFFFF)


def _pad_or_clip_utf8(text: str, size: int) -> bytes:
    raw = (text or "").encode("utf-8")
    if len(raw) >= size:
        return raw[:size]
    return raw + b"\x00" * (size - len(raw))


def _to_utf8_bytes(text: str) -> bytes:
    return (text or "").encode("utf-8")


def _sum32(data: bytes) -> int:
    return sum(data) & 0xFFFFFFFF


# Decoder and Encoder

class MessageDecoder:
    """Handles incoming messages"""

    @staticmethod
    def parse(raw_data: bytes) -> Tuple[Optional[int], Optional[bytes]]:
        if len(raw_data) < _LE_U8_U16_U16_U32.size:
            return None, None

        try:
            ver, mtype, data_len, integrity = _LE_U8_U16_U16_U32.unpack_from(raw_data, 0)
        except struct.error:
            return None, None

        if ver != 1:
            return None, None

        total = _LE_U8_U16_U16_U32.size + data_len
        if len(raw_data) < total:
            return None, None

        payload = raw_data[_LE_U8_U16_U16_U32.size:total]
        return int(mtype), payload


class ResponseEncoder:
    """Handles outgoing responses"""

    __slots__ = ("version",)

    def __init__(self, version: int) -> None:
        self.version = int(version)

    def create(self, msg_type: int, message_body: bytes = b"") -> bytes:
        mv = memoryview(message_body or b"")
        checksum = _sum32(mv)
        header = _LE_U8_U16_U16_U32.pack(self.version, int(msg_type), len(mv), checksum)
        return header + mv.tobytes()


# Builders

class ResponseBuilders:
    """Create a different types of responses"""

    __slots__ = ("_enc",)

    def __init__(self, encoder: ResponseEncoder) -> None:
        self._enc = encoder

    def registration_response(self, is_success: bool, user_identifier: str = "", status_text: str = "") -> bytes:
        if is_success:
            # 16 bytes user id + status as utf-8
            user_id = _pad_or_clip_utf8(user_identifier, 16)
            msg = user_id + _to_utf8_bytes(status_text)
            return self._enc.create(MessageTypes.REGISTER_OK, msg)
        else:
            return self._enc.create(MessageTypes.REGISTER_ERR, _to_utf8_bytes(status_text))

    def error_response(self, error_text: str) -> bytes:
        return self._enc.create(MessageTypes.REGISTER_ERR, _to_utf8_bytes(error_text))

    def user_list_response(self, user_collection: List[Dict[str, Any]]) -> bytes:
        buf = io.BytesIO()
        buf.write(_le_u32(len(user_collection)))
        for item in user_collection:
            uid = _pad_or_clip_utf8(item.get("client_id", ""), 16)
            name = _pad_or_clip_utf8(item.get("name", ""), 255)
            buf.write(uid)
            buf.write(name)
        return self._enc.create(MessageTypes.USER_LIST, buf.getvalue())

    def key_response(self, is_success: bool, user_identifier: str = "", key_data: str = "", status_text: str = "") -> bytes:
        if is_success:
            uid = _pad_or_clip_utf8(user_identifier, 16)
            key_bytes = _pad_or_clip_utf8(key_data, 1024)
            body = uid + key_bytes + _to_utf8_bytes(status_text)
            return self._enc.create(MessageTypes.KEY_RETURN, body)
        else:
            return self._enc.create(MessageTypes.REGISTER_ERR, _to_utf8_bytes(status_text))

    def message_list_response(self, message_collection: List[Dict[str, Any]]) -> bytes:
        out = io.BytesIO()
        out.write(_le_u32(len(message_collection)))
        for msg in message_collection:
            sender_id_b = _pad_or_clip_utf8(msg.get("from_client_id", ""), 16)
            msg_id = int(msg.get("id", 0)) & 0xFFFFFFFF
            msg_type_byte = int(msg.get("message_type", 0)) & 0xFF
            content_bytes = _to_utf8_bytes(msg.get("content", ""))
            sender_name_b = _pad_or_clip_utf8(msg.get("sender_name", "Unknown"), 255)

            out.write(sender_id_b)
            out.write(_LE_U32.pack(msg_id))
            out.write(_u8(msg_type_byte))
            out.write(_LE_U32.pack(len(content_bytes)))
            out.write(content_bytes)
            out.write(sender_name_b)

        return self._enc.create(MessageTypes.MSG_LIST, out.getvalue())

    def message_send_response(self, is_success: bool, status_text: str = "") -> bytes:
        body = _to_utf8_bytes(status_text)
        return self._enc.create(MessageTypes.MSG_SEND_OK if is_success else MessageTypes.MSG_SEND_ERR, body)


# High-level protocol

class CommunicationEngine:
    """Protocol handler"""

    __slots__ = ("_enc", "_bld")

    def __init__(self) -> None:
        self._enc = ResponseEncoder(1)
        self._bld = ResponseBuilders(self._enc)

    # Core protocol methods
    def decode_incoming(self, raw_data: bytes) -> Tuple[Optional[int], Optional[bytes]]:
        return MessageDecoder.parse(raw_data)

    def encode_outgoing(self, msg_type: int, message_body: bytes = b"") -> bytes:
        return self._enc.create(msg_type, message_body)

    # Response building methods
    def build_register_reply(self, is_success: bool, user_identifier: str = "", status_text: str = "") -> bytes:
        return self._bld.registration_response(is_success, user_identifier, status_text)

    def build_failure_reply(self, error_text: str) -> bytes:
        return self._bld.error_response(error_text)

    def build_user_list_reply(self, user_collection: List[Dict[str, Any]]) -> bytes:
        return self._bld.user_list_response(user_collection)

    def build_key_reply(self, is_success: bool, user_identifier: str = "", key_data: str = "", status_text: str = "") -> bytes:
        return self._bld.key_response(is_success, user_identifier, key_data, status_text)

    def build_message_list_reply(self, message_collection: List[Dict[str, Any]]) -> bytes:
        return self._bld.message_list_response(message_collection)

    def build_message_send_reply(self, is_success: bool, status_text: str = "") -> bytes:
        return self._bld.message_send_response(is_success, status_text)