# This Python script creates two files:
# private.pem 
# public.pem
# with 2048-bit public-private RSA keypairs

from Crypto.PublicKey import RSA
# Generate 2048 bits keys
key = RSA.generate(2048)
# Private key
private_key = key.export_key()
try:
    file_out = open("private.pem", "wb")
    file_out.write(private_key)
    print("[+] Private keyring file written...")
except IOError:
    msg = "Unable to create Private Key File, private.pem, on disk"
    print(msg)
finally:
    file_out.close()

# Public key
try:
    public_key = key.publickey().export_key()
    file_out = open("public.pem", "wb")
    file_out.write(public_key)
    print("[+] Public keyring file written...")
except IOError:
    msg = "Unable to create Public Key File, public.pem, on disk"
    print(msg)
finally:
    file_out.close()
