import socket
from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
#from Crypto.Util.Padding import unpad, pad
from Crypto.Random import get_random_bytes
import base64, json

#KEY = b'ThisIsASecretKey123'[:16]

HOST = "127.0.0.1"
PORT = 65432

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(1)

print("Drone server is online and waiting for commands...")

conn, addr = server.accept()
print("connected by:", addr)

#DIFFIE-HELLMAN

server_key = ECC.generate(curve="P-256")
server_public_bytes = server_key.public_key().export_key(format="DER")

conn.sendall(len(server_public_bytes).to_bytes(2,"big") + server_public_bytes)

client_public_len = int.from_bytes(conn.recv(2), "big")
client_public_bytes = conn.recv(client_public_len)
client_public_key = ECC.import_key(client_public_bytes)

shared_secret = (server_key.d * client_public_key.pointQ).x.to_bytes()

AES_KEY = HKDF(
    master=shared_secret,
    key_len=16,
    salt=b"drone-session",
    hashmod=SHA256
)

print("Secure session established")


#Now we use Symmetric Data exchange

while True:
    data = conn.recv(2048)
    if not data:
        break
    nonce = data[:12]
    tag = data[12:28]
    ciphertext =  data[28:]
#     #decrypt message
    cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=nonce)
    try:
        command = cipher.decrypt_and_verify(ciphertext, tag).decode()
    except ValueError:
        print("ERROR: Message authentication failed")
        continue
    
    print("Received command: ", command)
#     decrypted_data = unpad(cipher.decrypt(cipthertext), AES.block_size)
#     command = decrypted_data.decode("utf-8")
#     print(f" Receive command: {command}")

    if command == "takeoff":
        response = "drone taking off"
    elif command == "land":
        response = "drone landing"
    else:
        response = f"unknown command: {command}"

     #encrypt response
    nonce = get_random_bytes(12)
    cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(response.encode())

    conn.sendall(nonce + tag + ct)

conn.close()
#     response_IV = get_random_bytes(16)
#     cipher_encrypt = AES.new(KEY, AES.MODE_CBC, response_IV)
#     encrypted_data = cipher_encrypt.encrypt(pad(response.encode("utf-8"), AES.block_size))
#     responde_packet = response_IV + encrypted_data
#     print(f"\nEncrypted data:{responde_packet}\n")
#     conn.sendall(responde_packet)

# conn.close()
