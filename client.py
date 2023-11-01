# client.py
# Vaughn Woerpel

import requests
from Crypto.Cipher import ChaCha20
from Crypto.Hash import SHA256
from base64 import b64decode, b64encode
import json
import time
import rsa
import sys

authentication_server = "192.168.2.1"
application_server = "192.168.2.3"

# Load rsa keys
def loadkeys():
    with open('keys/key.pub', 'rb') as p:
        pubkey = rsa.PublicKey.load_pkcs1(p.read())
    with open('keys/key.pem', 'rb') as p:
        privkey = rsa.PrivateKey.load_pkcs1(p.read())
    return privkey, pubkey

# Goofy loading dot printing
def print_loading_dots():
    for x in range(0,3):
        for i in range(4):
            sys.stdout.write('\r' + ' Waiting for authentication' + '.' * i)
            sys.stdout.flush()
            time.sleep(0.5)
        sys.stdout.write("\033[K")
        sys.stdout.write("\r" + "Waiting for authentication     ")

# Decryption function
def decrypt(secret, encrypted_response):
    # Generate the SHA256 hash of the secret
    key = SHA256.new()
    key.update(secret.encode())
    key = key.hexdigest()[0:32].encode()

    try:
        # Base 64 decode the nonce and ciphertext
        nonce = b64decode(encrypted_response['nonce'])
        ciphertext = b64decode(encrypted_response['ciphertext'])

        # Decrypt the ciphertext and return it
        cipher = ChaCha20.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.decode()
    except (ValueError, KeyError):
        return None
    
def rsa_encrypt(message, key):
    return rsa.encrypt(message.encode('ascii'), key)

def main():
    # Takes in user input
    print("\n Welcome to the Bit-Coin Vault\n\n Please enter your username and password")
    username = input(" [Username]: ")
    password = input(" [Password]: ")
    
    # RSA Encrypt the username and password
    _, pubkey = loadkeys()
    username = rsa_encrypt(username, pubkey)
    username = b64encode(username).decode('utf-8')
    password = rsa_encrypt(password, pubkey)
    password = b64encode(password).decode('utf-8')

    # Communicate with authentication server
    response = requests.post(f"http://{authentication_server}/api/authenticate", json={"username": username, "password": password})
    if response.ok:
        auth = decrypt(password, response.json())
        if auth is None:
            print(" Wuh oh! Those credentials don't look right to me.")
            return
    else:
        print(" Invalid response from authentication server")
        return
    
    auth = json.loads(auth.replace("'", "\""))

    # Now ask for stuff from the application server
    response = requests.post(f"http://{application_server}/api/bit-coin-vault", json=auth)
    if response.ok:
        response = response.json()
        if response['auth'] == "fail":
            print(" Authentication Failure! Access to the vault is not permitted.")
            return
        
        # Prints how much the bit coin is valued
        print("\n")
        print_loading_dots()
        sys.stdout.write("\r" + " Success!                                    \n\n")
        print(f" At this moment, your bit-coin is worth {response['bit-coin']}")



if __name__ == "__main__":
    main()