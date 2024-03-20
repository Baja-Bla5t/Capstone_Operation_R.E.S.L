import Cryptodome
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP

#Function that creates a key pair and saves the key pair to private and public pem files 
def create_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    with open("private.pem", "wb") as f:
        f.write(private_key)

    public_key = key.publickey().exportKey()
    with open("public.pem", "wb") as f:    
        f.write(public_key)
    
#Function to encrypt a file using the key pair
def encrypt_data(data):
    
    #Imports public key and creates a session key
    recipient_key = RSA.importKey(open("public.pem").read())
    session_key = get_random_bytes(16)
    
    #Encrypts the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encoded_session_key = cipher_rsa.encrypt(session_key)
    
    #Encrypts the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    
    with open("encrypted_data.bin", "wb") as f:
        f.write(encoded_session_key)
        f.write(cipher_aes.nonce)
        f.write(tag)
        f.write(ciphertext)


#Function to decrypt data
def decrypt_data():
    private_key = RSA.importKey(open("private.pem").read())
    
    with open("encrypted_data.bin", "rb") as f:
        enc_session_key = f.read(private_key.size_in_bytes())
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()
        
    #Decrypts the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    
    #Decrypts the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    print(data.decode("UTF-8"))    
        
#Main Loop
user_input = "-1"
while user_input != "0":
    user_input = input("Options:\n 0. Exit\n 1. Encrypt data\n 2. Decrypt data\n 3. Create new key\n")
    
    if user_input == "1":
        data = input("Input data:\n").encode("utf-8")
        encrypt_data(data)
        with open("encrypted_data.bin", "rb") as f:
            encrypted_string = f.read()
        print(encrypted_string)
        
    elif user_input == "2":
        decrypt_data()
        
    elif user_input == "3":
        create_key_pair()
            
