# !/usr/bin/python3
# RSA_keys.py
# David Arboledas Brihuega
# January 2022
# usage: python RSA_keys.py <bitslenght>
# --------------------------------------------
# The script generates a public and private 
# RSA key pair of the desired length.
# Only  1024, 2048 and 4096 bits are possible
# --------------------------------------------


import sys
from Crypto.PublicKey import RSA

def main():
    # possible key length in bits
    valid_length_keys = [1024,2048,4096]
    try:
        length = int(sys.argv[1])
        if (length in valid_length_keys):
            generate_key(length)       
        else:
            print("That was no valid length")
    except ValueError:
        print("Oops! That was no valid input. Try again...")

      
def generate_key(length):
    print("[] Generating", length, "bits RSA key pair...")
    key = RSA.generate(length)
        
    # Private key
    private_key = key.export_key()
    try:
        file_out = open("private.pem", "wb")
        file_out.write(private_key)
        print("    [+] Private keyring file written...")
    except IOError:
        msg = "Unable to create Private Key File, private.pem, on disk"
        print(msg)
    finally:
        file_out.close()

    # Public key
    public_key = key.publickey().export_key()
    try:
        file_out = open("public.pem", "wb")
        file_out.write(public_key)
        print("    [+] Public keyring file written...")
    except IOError:
        msg = "Unable to create Public Key File, public.pem, on disk"
        print(msg)
    finally:
        file_out.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python RSA_keys.py <bitslenght>")
    else:
        main()