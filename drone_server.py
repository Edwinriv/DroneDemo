import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from Crypto.Random import get_random_bytes

KEY = b'ThisIsASecretKey123'[:16]

HOST = "127.0.0.1"
PORT = 65432

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(1)

print("Drone server is online and waiting for commands...")

conn, addr = server.accept()
print("connected by:", addr)

while True:
    data = conn.recv(1024)
    if not data:
        break
    IV = data[:16]
    cipthertext = data[16:]
    #decrypt message
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    decrypted_data = unpad(cipher.decrypt(cipthertext), AES.block_size)
    command = decrypted_data.decode("utf-8")
    print(f" Receive command: {command}")

    if command == "takeoff":
        response = "drone taking off"
    elif command == "land":
        response = "drone landing"
    else:
        response = f"unknown command: {command}"

    #encrypt response
    response_IV = get_random_bytes(16)
    cipher_encrypt = AES.new(KEY, AES.MODE_CBC, response_IV)
    encrypted_data = cipher_encrypt.encrypt(pad(response.encode("utf-8"), AES.block_size))
    responde_packet = response_IV + encrypted_data
    print(f"\nEncrypted data:{responde_packet}\n")
    conn.sendall(responde_packet)

conn.close()
