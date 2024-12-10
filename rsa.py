from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import os

# ======== support functions for part b and d ========
def find_decrypt_key(message, dir="key_pairs/"):
    # iterate through all the keys in the directory
    for file in os.listdir(dir):
        # filter out non .pem files
        if not file.endswith("_priv.pem"): 
            continue # skip to the next file
        elif decrypt_message(message, dir + file, "temp.txt"): # if the decryption is successful
            os.remove("temp.txt") # remove the temporary file
            return dir + file # return the private key file name

def find_sign_key(message, signature, dir="key_pairs/"):
    # iterate through all public key files in the directory
    for file in os.listdir(dir):
        # filter out non .pem files
        if not file.endswith("_pub.pem"):
            continue # skip to the next file
        public_key_path = os.path.join(dir, file)
        if verify_message(message, signature, public_key_path):
            return public_key_path
    return None # reutrn none if no valid key found

# ======== main functions ========
# Generate a public/private key pair using 2048 bits key length
def generate_keys(public_fname="public.pem", private_fname="private.pem"):
    # generate the key pair
    key = RSA.generate(2048)

    # ======= public key =======
    # extract the public key
    pub = key.publickey()
    pub_pem = pub.export_key(format='PEM')

    # save the public key in a file called public.pem
    with open(public_fname, 'wb') as f:
        f.write(pub_pem)

    # ======= private key =======
    # extract the private key
    pem = key.export_key(format='PEM')

    # save the private key in a file called private.pem
    with open(private_fname, 'wb') as f:
        f.write(pem)

# Encrypt a message using a public key
def encrypt_message(message, pub_key_path, out_fname="encrypted.txt"):

    # encrypt the message with the public RSA key using PKCS1_OAEP
    key = RSA.importKey(open(pub_key_path).read())
    cipher = PKCS1_OAEP.new(key)
    encrypted_message = cipher.encrypt(message)

    # write the encrypted message to the file
    with open(out_fname, 'wb') as f:
        f.write(encrypted_message)
    
# Decrypt a message using a private key
def decrypt_message(message, priv_key_path, out_fname="decrypted.txt"):
    # decrypt the message with the private RSA key using PKCS1_OAEP
    # and return True if the decryption is successful
    try:

        # open and read private key
        with open(priv_key_path, 'rb') as f:
            prikey_pem = f.read()

        # import private key  
        prikey = RSA.importKey(prikey_pem)

        # generate cipher using PKCS1_OAEP
        cipher = PKCS1_OAEP.new(prikey)

        # decrypt
        decrypted_message = cipher.decrypt(message)
        
        # write the decrypted message to the file
        with open(out_fname, 'wb') as f:
            f.write(decrypted_message)

        # return True if decryption is successful
        print("The private key is valid.")
        return True
    
    except ValueError:
        # return False if decryption is unsuccessful
        print("The private key is invalid.")
        return False

# Sign a message using a private key
def sign_message(message, priv_key_path, out_fname="signed_msg.txt"):

    # import private key
    with open(priv_key_path, 'rb') as f:
        private_key = RSA.importKey(f.read())

    # hash the message with SHA256
    hash = SHA256.new(message)

    # sign the message with the private RSA key using pkcs1_15
    pk = pkcs1_15.new(private_key)
    sm = pk.sign(hash)

    # write the signature to the file
    with open(out_fname,'wb') as f:
        f.write(sm)

# Verify a message using a public key
def verify_message(message, signature, public_key_path):
    # import public key
    key = RSA.importKey(open(public_key_path).read())

    # hash the message with SHA256
    hash = SHA256.new(message)

    # verify the signature with the public RSA key using pkcs1_15
    try:
        pkcs1_15.new(key).verify(hash, signature)
        print("The signature is valid.")
        return True
    except (ValueError, TypeError):
        print("The signature is not valid.")
        return False


def print_menu():
    """Prints the menu of options"""
    print("*******************Main Menu*******************")
    print('a. Generate public and private keys')
    print('b. Find the right key and decrypt the message in sus.txt')
    print('c. Sign a message and verify it')
    print('d. Find Miss Reveille\'s key pair that she used to sign rev.txt')
    print('q. Quit')
    print('***********************************************\n')

if __name__ == "__main__":
    while True:
        print_menu()
        option = input('Choose a menu option: ')

        if option == "a":
            # part a.1: generate public and private keys
            generate_keys()
           
            # part a.2: ask a message to be encrypted and encrypt it
            message = input("Enter a message to be encrypted: ")
            message = message.encode()
            public_key_path = "public.pem"

            # call the encrypt_message function
            encrypt_message(message, public_key_path)

            # part a.3: decrypt that exact message and output it to a file 
            #           called decrypted.txt
            private_key_path = "private.pem"
            encrypted_message = open("encrypted.txt", "rb").read()

            # call the decrypt_message function
            decrypt_message(encrypted_message, private_key_path)
            
        elif option == "b":
            # part b: decrypt the message given in sus.txt using one of the keys in key_pairs
            #         and output the decrypted message to a file called sus_decrypted.txt
            #         HINT: use the find_decrypt_key function to your advantage
            message = open("sus.txt", "rb").read()

            # find the correct private key
            private_key_path = find_decrypt_key(message)

            # decrypt the message with this private key
            if private_key_path:
                if decrypt_message(message, private_key_path, "sus_decrypted.txt"):
                    print(f"Message successfully decrypted using {private_key_path}.")
                else:
                    print("Decryption failed with the identified private key.")
            else:
                print("No valid private key was found in the key_pairs/ directory.")

    
        elif option == "c":
            # part c.1: sign a message using the private key from part a.1
            #           and export the signature to a file called signed_msg.txt
            message = input("Enter a message to be signed: ")
            message = message.encode()
            private_key_path = "private.pem"
            sign_message(message, private_key_path)

            # part c.2: verify the signature of the message using 
            #           the public key from part a.1 
            public_key_path = "public.pem"
            signature = open("signed_msg.txt", "rb").read()
            # call the verify_message function
            verify_message(message, signature, public_key_path)
        
        elif option == "d":
            # part d: identify the real Reveille's signature
            #         by verifying the signature of the message in 
            #         sus_decrypted.txt
            #         HINT:
            #         - think about how to find the correct key IRL (trial and error)
            #         - you are more than welcome to write a helper function to find the key
            #           and if you do, you can write find_sign_key() function
            #         - whatever method you use, as long as we select this option and get the
            #           correct key, you will get full credit
            message = open("sus_decrypted.txt", "rb").read()
            signature = open("rev.txt", "rb").read()
            public_key_path = find_sign_key(message, signature)

            if public_key_path:
                print(f"The correct public key is {public_key_path}.")
            else:
                print("No valid public key was found.")
            
        elif option == "q":
            break
