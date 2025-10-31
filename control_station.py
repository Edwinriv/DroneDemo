import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEY = b'ThisIsASecretKey123'[:16]
IV = b'ThisIsAnInitVect'[:16]
HOST = "127.0.0.1"
PORT = 65432

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))
print("Connected to dron server")

while True:
    command = input("Enter command(takeoff, land, quit):").strip()
    if command == "quit":
        break

    #Encrypt the command:
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted_data = cipher.encrypt(pad(command.encode("utf-8"), AES.block_size))
    print(f"\nEncrypted data: {encrypted_data}\n ")

    client.sendall(encrypted_data)

    cipher_decrypt = AES.new(KEY, AES.MODE_CBC, IV)
    response = client.recv(1024)
    decrypted_data = unpad(cipher_decrypt.decrypt(response), AES.block_size)
    decrypted_response = decrypted_data.decode("utf-8")
    print(f"Drone response: {decrypted_response}")

client.close()