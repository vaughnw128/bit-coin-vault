# application-server.py
# Vaughn Woerpel

from flask import Flask, jsonify, request
from Crypto.Cipher import ChaCha20
from Crypto.Hash import SHA256
from base64 import b64decode
import random
import json
import requests
requests.packages.urllib3.disable_warnings() 

app = Flask(__name__)

# Define the bit coin and secret key
bit_coin = 0b0
secret_key = "ogion"

# ChaCha20 decrypt
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

# Bit coin vault endpoint
@app.route('/api/bit-coin-vault', methods=['POST'])
def authenticate():
    # Decrypt the token from the client
    token = decrypt(secret_key, request.json['token'])

    # Verify the token
    if token is None:
        return jsonify({'auth': 'fail', 'bit-coin': 'null'})
    
    # Verify against the oauth provider via https
    data = {'access_token': token}
    verify = requests.post('https://192.168.2.2/resource.php', data=data, verify=False)
    if verify.ok:
        verify = json.loads(verify.content.decode())
        if verify["success"]:
            print(verify["message"])
        else:
            return jsonify({'auth': 'fail', 'bit-coin': 'null'})
    else:
        return jsonify({'auth': 'fail', 'bit-coin': 'null'})
        

    # Send the bit coin data to the client
    bit_coin = random.getrandbits(1)
    print(f"Authentication Token: {token}")
    return jsonify({'auth': 'success', 'bit-coin': bit_coin})
    

if __name__ == '__main__':
    app.run(debug=True)