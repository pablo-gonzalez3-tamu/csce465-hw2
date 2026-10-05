import os
import hashlib
import hmac

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

PROTOCOL_LABEL = b"CSCE465-HS-v2"
GROUP_ID = b"ffdhe3072"

GATEWAY_ID = b"gateway-01"
NODE_ID = b"node-01"

ROLE_GATEWAY = b"gateway"
ROLE_NODE = b"node"

DH_WIDTH = 384


def load_dh_parameters(filename = "ffdhe3072.pem"):
    with open(filename, "rb") as f:
        return serialization.load_pem_parameters(f.read())


def encode_fields(data):
    return len(data).to_bytes(4, "big") + data


def parse_field(encoded, expected_count = 8):
    fields = []
    offset = 0

    for _ in range(expected_count):
        if offset + 4 > len(encoded):
            raise ValueError("missing length field")
        

        length = int.from_bytes(encoded[offset:offset + 4], "big")
        offset += 4

        if offset + length > len(encoded):
            raise ValueError("incorrect field lengths")
        
        field = encoded[offset:offset + length]
        offset += length
        fields.append(field)
    

    if offset != len(encoded):
        raise ValueError("extra trailing bytes")

    return fields


def encode_dh_public(public_key):
    y = public_key.public_numbers().y
    return y.to_bytes(DH_WIDTH, "big")


def build_transcript(gateway_id, node_id, gateway_public, node_public, gateway_nonce, node_nonce,):
    fields = [PROTOCOL_LABEL, GROUP_ID, gateway_id, node_id, gateway_public, node_public, gateway_nonce, node_nonce,]

    return b"".join(encode_fields(field) for field in fields)


def validate_transcript(transcript):
    fields = parse_field(transcript)

    protocol_label = fields[0]
    group_id = fields[1]
    gateway_id = fields[2]
    node_id = fields[3]
    gateway_public = fields[4]
    node_public = fields[5]
    gateway_nonce = fields[6]
    node_nonce = fields[7]

    if protocol_label != PROTOCOL_LABEL:
        raise ValueError("unexpected protocol label")

    if group_id != GROUP_ID:
        raise ValueError("unexpected group id")
    
    if len(gateway_public) != DH_WIDTH:
        raise ValueError("Gateway DH public value must be 384 bytes")
    
    if len(node_public) != DH_WIDTH:
        raise ValueError("Node DH public value must be 384 bytes")
    
    if len(gateway_nonce) != 16:
        raise ValueError("Gateway nonce must be 16 bytes")
    
    if len(node_nonce) != 16:
        raise ValueError("Node nonce must be 16 bytes")

    return {
        "gateway_id": gateway_id,
        "node_id": node_id,
        "gateway_public": gateway_public,
        "node_public": node_public,
        "gateway_nonce": gateway_nonce,
        "node_nonce": node_nonce,
    }


def transcript_hash(transcript):
    return hashlib.sha256(transcript).digest()

def sign_handshake(private_key, role, th):
    data = role + th

    return private_key.sign(
        data,
        padding.PSS(
            mgf = padding.MGF1(hashes.SHA256()),
            salt_length = padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_handshake(public_key, role, th, signature):
    public_key.verify(
        signature,
        role + th,
        padding.PSS(
            mgf = padding.MGF1(hashes.SHA256()),
            salt_length = padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256()
    )

def derive_keys(shared_secret, th):
    z_int = int.from_bytes(shared_secret, "big")
    Z = z_int.to_bytes(DH_WIDTH, "big")


    K_master = hashlib.sha256(b"CSCE465-KDF-v1" + Z + th).digest()

    K_g2n_enc = hmac.new(K_master, b"gateway-to-node encryption" + th, hashlib.sha256,).digest()

    K_g2n_mac = hmac.new(K_master, b"gateway-to-node MAC" + th, hashlib.sha256,).digest()

    K_n2g_enc = hmac.new(K_master, b"node-to-gateway encryption" + th, hashlib.sha256,).digest()

    k_n2g_mac = hmac.new(K_master, b"node-to-gateway MAC" + th, hashlib.sha256,).digest()

    session_id = hmac.new(K_master, b"session identifier" + th, hashlib.sha256,).digest()[:8]

    return {
        "K_master": K_master,
        "K_g2n_enc": K_g2n_enc,
        "K_g2n_mac": K_g2n_mac,
        "K_n2g_enc": K_n2g_enc,
        "K_n2g_mac": k_n2g_mac,
        "session_id": session_id,
    }



def run_handshake(parameters, gateway_rsa, node_rsa):
    gateway_dh_private = parameters.generate_private_key()
    node_dh_private = parameters.generate_private_key()

    gateway_dh_public = gateway_dh_private.public_key()
    node_dh_public = node_dh_private.public_key()

    gateway_public_bytes = encode_dh_public(gateway_dh_public)
    node_public_bytes = encode_dh_public(node_dh_public)

    gateway_nonce = os.urandom(16)
    node_nonce = os.urandom(16)

    
    transcript = build_transcript(GATEWAY_ID, NODE_ID, gateway_public_bytes, node_public_bytes, gateway_nonce, node_nonce,)

    parsed = validate_transcript(transcript)

    if parsed["gateway_id"] != GATEWAY_ID:
        raise ValueError("unexpected gateway identity")
    
    if parsed["node_id"] != NODE_ID:
        raise ValueError("unexpected node identity")
    
    th = transcript_hash(transcript)


    gateway_signature = sign_handshake(gateway_rsa, ROLE_GATEWAY, th,)
    node_signature = sign_handshake(node_rsa, ROLE_NODE, th,)

    verify_handshake(gateway_rsa.public_key(), ROLE_GATEWAY, th, gateway_signature,)
    verify_handshake(node_rsa.public_key(), ROLE_NODE, th, node_signature,)


    gateway_Z = gateway_dh_private.exchange(node_dh_public)
    node_Z = node_dh_private.exchange(gateway_dh_public)

    if gateway_Z != node_Z:
        raise ValueError("Dh shared secrets do not match")

    
    gateway_keys = derive_keys(gateway_Z, th)
    node_keys = derive_keys(node_Z, th)

    return {
        "transcript": transcript,
        "th": th,
        "gateway_signature": gateway_signature,
        "node_signature": node_signature,
        "gateway_keys": gateway_keys,
        "node_keys": node_keys,
        "gateway_public": gateway_public_bytes,
        "node_public": node_public_bytes,
        "gateway_nonce": gateway_nonce,
        "node_nonce": node_nonce,
    }


def test_bad_signature(result, node_rsa):
    bad_signature = bytearray(result["node_signature"])
    bad_signature[0] ^= 1

    try:
        verify_handshake(node_rsa.public_key(), ROLE_NODE, result["th"], bytes(bad_signature),)
        print("Bad signature test: FAILED")
    except InvalidSignature:
        print("Bad signature test: REJECTED correctly")
    

def test_changed_nonce(result, node_rsa):
    changed_nonce = bytearray(result["node_nonce"])
    changed_nonce[0] ^= 1

    tampered_transcript = build_transcript(GATEWAY_ID, NODE_ID, result["gateway_public"], result["node_public"], result["gateway_nonce"], bytes(changed_nonce),)

    validate_transcript(tampered_transcript)
    tampered_th = transcript_hash(tampered_transcript)

    try:
        verify_handshake(node_rsa.public_key(), ROLE_NODE, tampered_th, result["node_signature"],)
        print("Changed nonce test: FAILED")
    except InvalidSignature:
        print("Changed nonce test: REJECTED correctly")


def test_changed_public_value(result, node_rsa):
    changed_public = bytearray(result["node_public"])
    changed_public[-1] ^= 1

    tampered_transcript = build_transcript(GATEWAY_ID, NODE_ID, result["gateway_public"], bytes(changed_public), result["gateway_nonce"], result["node_nonce"],)

    validate_transcript(tampered_transcript)
    tampered_th = transcript_hash(tampered_transcript)

    try:
        verify_handshake(node_rsa.public_key(), ROLE_NODE, tampered_th, result["node_signature"],)
        print("Changed public value test: FAILED")
    except InvalidSignature:
        print("Changed public value test: REJECTED correctly")


def test_bad_length(result):
    malformed = bytearray(result["transcript"])

    original_length = int.from_bytes(malformed[0:4], "big")
    malformed[0:4] = (original_length + 5).to_bytes(4, "big")

    try:
        validate_transcript(bytes(malformed))
        print("Malformed transcript test: FAILED")
    except ValueError:
        print("Malformed transcript test: REJECTED correctly")


def test_wrong_identity(result):
    wrong_transcript = build_transcript(GATEWAY_ID, b"evil-node", result["gateway_public"], result["node_public"], result["gateway_nonce"], result["node_nonce"],)

    parsed = validate_transcript(wrong_transcript)

    try:
        if parsed["node_id"] != NODE_ID:
            raise ValueError("Unexpected node identity")
        
        print("wrong identity test: FAILED")
    except ValueError:
        print("Wrong identity test: REJECTED correctly")


def test_reflection(result, gateway_rsa):
    try:
        verify_handshake(gateway_rsa.public_key(), ROLE_NODE, result["th"], result["gateway_signature"],)
        print("Reflection test: FAILED")
    except InvalidSignature:
        print("Reflection test: REJECTED correctly")


def main():
    parameters = load_dh_parameters()

    from cryptography.hazmat.primitives.asymmetric import rsa 

    gateway_rsa = rsa.generate_private_key(public_exponent = 65537, key_size = 3072,)

    node_rsa = rsa.generate_private_key(public_exponent = 65537, key_size = 3072,)

    print("running authenticated Diffie-Hellman handshake...")

    result = run_handshake(parameters, gateway_rsa, node_rsa,)

    gateway_keys = result["gateway_keys"]
    node_keys = result["node_keys"]

    print("Handshake accepted")
    print("Gateway identity:", GATEWAY_ID.decode())
    print("Node identity:", NODE_ID.decode())
    print("Transcript hash:", result["th"].hex())
    print("Session ID:", gateway_keys["session_id"].hex())

    same_keys = (
        gateway_keys["K_g2n_enc"] == node_keys["K_g2n_enc"]
        and gateway_keys["K_g2n_mac"] == node_keys["K_g2n_mac"]
        and gateway_keys["K_n2g_enc"] == node_keys["K_n2g_enc"]
        and gateway_keys["K_n2g_mac"] == node_keys["K_n2g_mac"]
        and gateway_keys["session_id"] == node_keys["session_id"]
    )

    print("Gateway and node derived identical keys:", same_keys)

    print("-----Rejection tests------")

    test_bad_signature(result, node_rsa)
    test_changed_nonce(result, node_rsa)
    test_changed_public_value(result, node_rsa)
    test_bad_length(result)
    test_wrong_identity(result)
    test_reflection(result, gateway_rsa)


if __name__ == "__main__":
    main()