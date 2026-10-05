import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature


VERSION = 1

DIR_GATEWAY_TO_NODE = 0
DIR_NODE_TO_GATEWAY = 1


class RecordError(Exception):
    """Raised whenever a record fails validation."""
    pass


class SecureRecordLayer:
    def __init__(
        self,
        session_id,
        send_key_enc,
        send_key_mac,
        recv_key_enc,
        recv_key_mac,
        send_direction,
        recv_direction,
    ):
        if len(session_id) != 8:
            raise ValueError("session_id must be exactly 8 bytes")

        if len(send_key_enc) != 32 or len(recv_key_enc) != 32:
            raise ValueError("AES-256 keys must be 32 bytes")

        if len(send_key_mac) != 32 or len(recv_key_mac) != 32:
            raise ValueError("HMAC keys must be 32 bytes")

        if send_direction not in (0, 1):
            raise ValueError("Invalid send direction")

        if recv_direction not in (0, 1):
            raise ValueError("Invalid receive direction")

        if send_direction == recv_direction:
            raise ValueError("Send and receive directions must differ")

        self.session_id = session_id

        self.send_key_enc = send_key_enc
        self.send_key_mac = send_key_mac

        self.recv_key_enc = recv_key_enc
        self.recv_key_mac = recv_key_mac

        self.send_direction = send_direction
        self.recv_direction = recv_direction

        self.send_sequence = 0
        self.recv_sequence = 0

    def seal(self, message_type, plaintext):
        """
        Encrypt and authenticate one outgoing record.
        """

        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")

        if not 0 <= message_type <= 255:
            raise ValueError("message_type must fit in one byte")

        sequence = self.send_sequence

        if sequence > 0xFFFFFFFFFFFFFFFF:
            raise RecordError("send sequence exhausted")


        iv = self.session_id + sequence.to_bytes(8, "big")

        cipher = Cipher(
            algorithms.AES(self.send_key_enc),
            modes.CTR(iv)
        )

        encryptor = cipher.encryptor()

        ciphertext = (
            encryptor.update(plaintext)
            + encryptor.finalize()
        )


        header = struct.pack(
            ">BBQBI",
            VERSION,
            self.send_direction,
            sequence,
            message_type,
            len(ciphertext),
        )


        mac = hmac.HMAC(
            self.send_key_mac,
            hashes.SHA256()
        )

        mac.update(header)
        mac.update(iv)
        mac.update(ciphertext)

        tag = mac.finalize()

        self.send_sequence += 1

        return header + iv + ciphertext + tag



    def open_record(self, record):
        """
        Authenticate and decrypt one incoming record.

        Returns:
            (message_type, plaintext)

        Raises:
            RecordError on any invalid record.
        """

        if not isinstance(record, bytes):
            raise TypeError("record must be bytes")


        HEADER_LEN = 15

        IV_LEN = 16

        TAG_LEN = 32

        minimum_length = HEADER_LEN + IV_LEN + TAG_LEN

        if len(record) < minimum_length:
            raise RecordError("invalid record")


        header = record[:HEADER_LEN]

        try:
            (
                version,
                direction,
                sequence,
                message_type,
                ciphertext_length,
            ) = struct.unpack(">BBQBI", header)
        except struct.error:
            raise RecordError("invalid record")

        expected_total_length = (
            HEADER_LEN
            + IV_LEN
            + ciphertext_length
            + TAG_LEN
        )

        if len(record) != expected_total_length:
            raise RecordError("invalid record")

        iv_start = HEADER_LEN
        iv_end = iv_start + IV_LEN

        ciphertext_start = iv_end
        ciphertext_end = ciphertext_start + ciphertext_length

        iv = record[iv_start:iv_end]
        ciphertext = record[ciphertext_start:ciphertext_end]
        tag = record[ciphertext_end:]


        if version != VERSION:
            raise RecordError("invalid record")

        if direction != self.recv_direction:
            raise RecordError("invalid record")

        if sequence != self.recv_sequence:
            raise RecordError("invalid record")

        expected_iv = (
            self.session_id
            + sequence.to_bytes(8, "big")
        )

        if iv != expected_iv:
            raise RecordError("invalid record")

        mac = hmac.HMAC(
            self.recv_key_mac,
            hashes.SHA256()
        )

        mac.update(header)
        mac.update(iv)
        mac.update(ciphertext)

        try:

            mac.verify(tag)
        except InvalidSignature:
            raise RecordError("invalid record")


        cipher = Cipher(
            algorithms.AES(self.recv_key_enc),
            modes.CTR(iv)
        )

        decryptor = cipher.decryptor()

        plaintext = (
            decryptor.update(ciphertext)
            + decryptor.finalize()
        )


        self.recv_sequence += 1

        return message_type, plaintext

