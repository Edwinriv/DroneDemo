import socket
from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
#from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64, json

#KEY = b'ThisIsASecretKey123'[:16]

HOST = "127.0.0.1"
PORT = 65432

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))
print("Connected to dron server")

server_pub_len = int.from_bytes(client.recv(2), "big")
server_pub_bytes = client.recv(server_pub_len)
server_pub_key = ECC.import_key(server_pub_bytes)

client_key = ECC.generate(curve="P-256")
client_public_bytes = client_key.public_key().export_key(format="DER")

client.sendall(len(client_public_bytes).to_bytes(2, "big") + client_public_bytes)

shared_secret = (client_key.d * server_pub_key.pointQ).x.to_bytes()

AES_KEY = HKDF(
    master=shared_secret,
    key_len=16,
    salt=b"drone-session",
    hashmod=SHA256
)

print("Secure session established")

while True:
    command = input("Enter command(takeoff, land, quit):").strip()
    if command == "quit":
        break

    nonce = get_random_bytes(12)
    cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(command.encode())

    client.sendall(nonce + tag + ciphertext)

    response = client.recv(2048)
    r_nonce = response[:12]
    r_tag = response[12:28]
    r_ct = response[28:]

    cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=r_nonce)
    plaintext = cipher.decrypt_and_verify(r_ct, r_tag)
    print("Drone response: ", plaintext.decode())

client.close()
#     IV = get_random_bytes(16)
#     #Encrypt the command:
#     cipher = AES.new(KEY, AES.MODE_CBC, IV)
#     encrypted_data = cipher.encrypt(pad(command.encode("utf-8"), AES.block_size))
#     print(f"\nEncrypted data: {encrypted_data}\n ")
#     packet = IV + encrypted_data
#     client.sendall(packet)

#     #decrypt response from the server
#     response = client.recv(1024)
#     response_iv = response[:16]
#     response_ct = response[16:]
#     cipher_decrypt = AES.new(KEY, AES.MODE_CBC, response_iv)
#     decrypted_data = unpad(cipher_decrypt.decrypt(response_ct), AES.block_size)
#     decrypted_response = decrypted_data.decode("utf-8")
#     print(f"Drone response: {decrypted_response}")

# client.close()
