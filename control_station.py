import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

KEY = b'ThisIsASecretKey123'[:16]

HOST = "127.0.0.1"
PORT = 65432

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))
print("Connected to dron server")

while True:
    command = input("Enter command(takeoff, land, quit):").strip()
    if command == "quit":
        break
    IV = get_random_bytes(16)
    #Encrypt the command:
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted_data = cipher.encrypt(pad(command.encode("utf-8"), AES.block_size))
    print(f"\nEncrypted data: {encrypted_data}\n ")
    packet = IV + encrypted_data
    client.sendall(packet)

    #decrypt response from the server
    response = client.recv(1024)
    response_iv = response[:16]
    response_ct = response[16:]
    cipher_decrypt = AES.new(KEY, AES.MODE_CBC, response_iv)
    decrypted_data = unpad(cipher_decrypt.decrypt(response_ct), AES.block_size)
    decrypted_response = decrypted_data.decode("utf-8")
    print(f"Drone response: {decrypted_response}")

client.close()