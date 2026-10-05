from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

PLAIN = b'{"action":"READ", "path":"notes.txt"}'

def aes_ctr_encrypt(key, nonce, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()

    return encryptor.update(plaintext) + encryptor.finalize()

def aes_ctr_decrypt(key, nonce, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()

    return decryptor.update(ciphertext) + decryptor.finalize()


def relay_modify(ciphertext, original, new):

    if len(original) != len(new):
        raise ValueError("Must have the same length")
    

    modified = bytearray(ciphertext)
    offset = PLAIN.index(original)


    #XOR Relation
    for i in range(len(original)):
        delta = original[i] ^ new[i]
        modified[offset + i] ^= delta

        print(f"{chr(original[i])} -> {chr(new[i])}: {original[i]:02x} XOR {new[i]:02x} = {delta:02x}")
    
    return bytes(modified)


def receiver(key, nonce, ciphertext):
    plaintext = aes_ctr_decrypt(key, nonce, ciphertext)
    print("Receiver: ", plaintext.decode())


def main():

    key = os.urandom(32) #AES 256
    nonce = os.urandom(16) #CTR initial counter value

    print("Original plaintaext: ", PLAIN.decode)

    ciphertext = aes_ctr_encrypt(key, nonce, PLAIN)

    print("Ciphertext: ", ciphertext.hex())


    #attacker changes READ -> LIST without knowing the key
    modified_ciphertext = relay_modify(ciphertext, b"READ", b"LIST")

    print("After relay modification: ")
    receiver(key,nonce, modified_ciphertext)

    print("Replay demondatration: ")
    receiver(key, nonce, ciphertext)
    receiver(key, nonce, ciphertext)


if __name__ == "__main__":
    main()