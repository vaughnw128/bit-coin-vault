# authentication-server.py
# Vaughn Woerpel

from flask import Flask, jsonify, request
import json
import requests
from Crypto.Cipher import ChaCha20
from Crypto.Hash import SHA256
from base64 import b64encode
import rsa
from base64 import b64decode
requests.packages.urllib3.disable_warnings() 

app = Flask(__name__)

# Define the secret key
secret_key = "ogion"

# Load rsa keys
def loadkeys():
    with open('keys/key.pub', 'rb') as p:
        pubkey = rsa.PublicKey.load_pkcs1(p.read())
    with open('keys/key.pem', 'rb') as p:
        privkey = rsa.PrivateKey.load_pkcs1(p.read())
    return privkey, pubkey

# ChaCha20 stream cipher encrypt
def encrypt(secret, content) -> str:
    # Generate hash from secret
    key = SHA256.new()
    key.update(secret.encode())
    key = key.hexdigest()[0:32].encode()

    # Encrypt with ChaCha20
    cipher = ChaCha20.new(key=key)
    ciphertext = cipher.encrypt(content.encode())
    
    # Encode in base64
    nonce = b64encode(cipher.nonce).decode('utf-8')
    ct = b64encode(ciphertext).decode('utf-8')
    
    result = {'nonce':nonce, 'ciphertext': ct}
    return result

# RSA decrypt
def rsa_decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except:
        return False

@app.route('/api/authenticate', methods=['POST'])
def authenticate():
    content = request.json

    print("== Authentication Request from Client ==")

    username = content['username']
    password = content['password']

    # Decrypt the password and username with RSA
    privkey, _ = loadkeys()
    username = rsa_decrypt(b64decode(username), privkey)
    password = rsa_decrypt(b64decode(password), privkey)

    # Show the username and password
    print(f"Username: {username}")
    print(f"Password: {password}")

    # Send a request to the oauth provider
    data = {'grant_type': 'client_credentials'}
    auth = requests.post('https://192.168.2.2/token.php', data=data, auth=(username, password), verify=False)
    
    # If the provider responds, load the json and encrypt it
    if auth.ok:
        auth = json.loads(auth.content.decode())
        print(f"Authentication Token: {auth['access_token']}")
        
        # Encrypt the token and put it inside encrypted response
        token = encrypt(secret_key, auth['access_token'])
        resp = encrypt(content['password'], str({'auth': 'success', 'token': token}))
        return resp
    else:
        return jsonify({'auth': 'fail', 'token': 'null'})

if __name__ == '__main__':
    app.run(debug=True)