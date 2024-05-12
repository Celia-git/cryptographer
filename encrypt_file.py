from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import sys
import os
import getpass

DECODEDIR = ".\\decoded\\"
ENCODEDIR = ".\\encoded\\"

# Read each file in directory
def read_infile(directory, code):
    file_data = {}
    input_list = os.listdir(directory)
    if len(input_list)==0:
        raise ValueError("Cannot %s: There are no files in %s directory" % (code, directory))
    for filename in input_list:
        lines = ""
        if os.path.isfile(directory+filename) and not (filename == "salt.txt"):
            with open(directory+filename, "rb") as infile:
                lines = infile.read()
                file_data[filename]=lines
            # Delete file at path
            os.remove(directory+filename)
    
    return file_data

    
# Encrypt Files in input directory
def encrypt_files(password):
    password = password.encode('utf-8')
    # read infiles
    file_data = read_infile(DECODEDIR, "encrypt")
    # iterate filenames
    for filename in file_data.keys():
        # Create a new key from password
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=1000000)
        key = base64.urlsafe_b64encode(kdf.derive(password))
        # encrypt data
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(file_data[filename])
        # save encrypted data in output directory
        with open(ENCODEDIR+filename, "wb") as outfile:
            outfile.write(encrypted_data)
        # save salt to text file
        with open(ENCODEDIR+"salt.txt", "ab+") as saltfile:
            saltfile.write(filename.encode("utf-8")+b"|"+salt+b"\n")

    print("Encrypted files saved in "+ENCODEDIR+" local directory")


# Decrypt Files in output directory
def decrypt_files(password):
    password = password.encode("utf-8")
    # Read encrypted files
    file_data = read_infile(ENCODEDIR, "decrypt")
    lines = []
    # Get salts
    with open(ENCODEDIR+"salt.txt", "rb") as salt_keys:
        lines = salt_keys.readlines()
    os.remove(ENCODEDIR+"salt.txt")
    # Iterate salts and filenames
    for line in lines:
        filename = line.split(b"|")[0].decode("utf-8")
        salt = line.split(b"|")[1].strip(b"\n")
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=1000000)
        key = base64.urlsafe_b64encode(kdf.derive(password))
        # Decrypt Data
        fernet = Fernet(key)
        encrypted = file_data[filename]
        decrypted_data = fernet.decrypt(encrypted)
        # Store decrypted data in file in input directory
        with open(DECODEDIR+filename, "wb") as outfile:
            outfile.write(decrypted_data)
            
    print("Decrypted files saved in " +DECODEDIR+ " local directory")
        

# Encode: Reads lines from infile
    # encrypts them
    # saves salt.txt
    # saves new encrypted file
    # deletes unencrypted file
# Decode: reads lines from infile
    # decrypts them
    # deletes salt and encrypted file
    # saves new unencrypted file
    
if __name__=="__main__":
    if (len(sys.argv)==2):
        password = getpass.getpass("Enter encryption password\n")
        confirm_password = getpass.getpass("Confirm encryption password\n")
        if password==confirm_password:
            if (sys.argv[1].startswith("e")):
                encrypt_files(password)
            elif (sys.argv[1].startswith("d")):
                decrypt_files(password)
    else:
        print("run program with arg1: encode/decode")
        

