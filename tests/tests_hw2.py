import pytest

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import InvalidSignature

from secure_record import (
    SecureRecordLayer,
    RecordError,
    DIR_GATEWAY_TO_NODE,
    DIR_NODE_TO_GATEWAY,
)

from handshake import (
    load_dh_parameters,
    run_handshake,
    sign_handshake,
    verify_handshake,
    ROLE_GATEWAY,
    ROLE_NODE,
)

def make_connected_pair():
    """
    Runs a valid authenticated handshake and creates
    gateway/node SecureRecordLayer objects.
    """

    parameters = load_dh_parameters("ffdhe3072.pem")

    gateway_rsa = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    node_rsa = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    result = run_handshake(parameters, gateway_rsa, node_rsa)

    gateway_keys = result["gateway_keys"]
    node_keys = result["node_keys"]

    gateway = SecureRecordLayer(
        session_id=gateway_keys["session_id"],

        send_key_enc=gateway_keys["K_g2n_enc"],
        send_key_mac=gateway_keys["K_g2n_mac"],

        recv_key_enc=gateway_keys["K_n2g_enc"],
        recv_key_mac=gateway_keys["K_n2g_mac"],

        send_direction=DIR_GATEWAY_TO_NODE,
        recv_direction=DIR_NODE_TO_GATEWAY,
    )

    node = SecureRecordLayer(
        session_id=node_keys["session_id"],

        send_key_enc=node_keys["K_n2g_enc"],
        send_key_mac=node_keys["K_n2g_mac"],

        recv_key_enc=node_keys["K_g2n_enc"],
        recv_key_mac=node_keys["K_g2n_mac"],

        send_direction=DIR_NODE_TO_GATEWAY,
        recv_direction=DIR_GATEWAY_TO_NODE,
    )

    return gateway, node, result, gateway_rsa, node_rsa




def test_valid_handshake_and_bidirectional_messages():
    gateway, node, result, gateway_rsa, node_rsa = make_connected_pair()

    assert (
        result["gateway_keys"]["session_id"]
        == result["node_keys"]["session_id"]
    )

    record1 = gateway.seal(
        message_type=1,
        plaintext=b"hello from gateway"
    )

    message_type1, plaintext1 = node.open_record(record1)

    assert message_type1 == 1
    assert plaintext1 == b"hello from gateway"

    record2 = node.seal(
        message_type=2,
        plaintext=b"hello from node"
    )

    message_type2, plaintext2 = gateway.open_record(record2)

    assert message_type2 == 2
    assert plaintext2 == b"hello from node"


def test_modified_ciphertext_rejected():
    gateway, node, _, _, _ = make_connected_pair()

    record = bytearray(
        gateway.seal(
            message_type=1,
            plaintext=b"READ notes.txt"
        )
    )

    ciphertext_index = 31

    record[ciphertext_index] ^= 0x01

    with pytest.raises(RecordError):
        node.open_record(bytes(record))

    assert node.recv_sequence == 0




def test_modified_authenticated_header_rejected():
    gateway, node, _, _, _ = make_connected_pair()

    record = bytearray(
        gateway.seal(
            message_type=1,
            plaintext=b"normal message"
        )
    )

    record[10] ^= 0x01

    with pytest.raises(RecordError):
        node.open_record(bytes(record))

    assert node.recv_sequence == 0



def test_replayed_record_rejected():
    gateway, node, _, _, _ = make_connected_pair()

    record = gateway.seal(
        message_type=1,
        plaintext=b"execute once"
    )

    message_type, plaintext = node.open_record(record)

    assert message_type == 1
    assert plaintext == b"execute once"

    assert node.recv_sequence == 1

    # Replay same record.
    with pytest.raises(RecordError):
        node.open_record(record)

    # Replay must not alter receiver state.
    assert node.recv_sequence == 1



def test_reflected_record_wrong_direction_rejected():
    gateway, node, _, _, _ = make_connected_pair()

    record = gateway.seal(
        message_type=1,
        plaintext=b"gateway command"
    )

    with pytest.raises(RecordError):
        gateway.open_record(record)

    assert gateway.recv_sequence == 0



def test_incorrect_rsa_public_key_rejected():
    correct_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
    )

    wrong_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
    )

    th = b"A" * 32

    signature = sign_handshake(
        correct_private_key,
        ROLE_GATEWAY,
        th
    )

    verify_handshake(
        correct_private_key.public_key(),
        ROLE_GATEWAY,
        th,
        signature
    )

    with pytest.raises(InvalidSignature):
        verify_handshake(
            wrong_private_key.public_key(),
            ROLE_GATEWAY,
            th,
            signature
        )



def test_modified_handshake_signature_rejected():
    _, _, result, _, node_rsa = make_connected_pair()

    bad_signature = bytearray(
        result["node_signature"]
    )

    bad_signature[0] ^= 0x01

    with pytest.raises(InvalidSignature):
        verify_handshake(
            node_rsa.public_key(),
            ROLE_NODE,
            result["th"],
            bytes(bad_signature)
        )




def test_reflected_handshake_signature_rejected():
    _, _, result, gateway_rsa, _ = make_connected_pair()

    with pytest.raises(InvalidSignature):
        verify_handshake(
            gateway_rsa.public_key(),
            ROLE_NODE,
            result["th"],
            result["gateway_signature"]
        )