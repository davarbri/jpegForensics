# !/usr/bin/python3
# IMobile.py
# David Arboledas Brihuega
# November 2021
# usage: pythom IMobile.py <jpeg file>
# -----------------------------------------------
# The script writes the mobile's IMEI,
# the image MD5 HASH and their RSA signature
# after the last End Of Image JPEG marker
# -----------------------------------------------

import sys
import binascii
import hashlib
import errno
import re

from Crypto.Hash import MD5
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

TRAILER_EOF = "ffd9"

# 15-digit IMEI is read from mobile, e.g.
IMEI = '458737169267790'

BIN_TRAILER_EOF = binascii.unhexlify(TRAILER_EOF)


def main():
    # script gets 'stamped' JPEG file
    temporary_image = sys.argv[1]
    final_image = 'IMobile_' + sys.argv[1]
    try:
        # and opens it to read it
        with open(temporary_image, 'rb') as temporary_file:
            bin_vector_data = temporary_file.read()
            # Original JPEG MD5 hash
            MD5 = hashlib.md5(bin_vector_data).hexdigest()
            # call to find the last 0xFFD9 marker offset
            jpeg_trailer_index = find_jpeg_last_trailer_index(bin_vector_data)

            if jpeg_trailer_index > 0:
                try:
                    with open(final_image, 'wb') as primary_image:
                        # IMEI + original JPEG MD5 hash string signed
                        # with IMobile's private RSA key
                        RSA_signature = signing_RSA(IMEI + MD5)
                        # JPEG_file is written with forensic data
                        # injecting IMEI + MD5 + RSA signature
                        primary_image.write(
                            inject_forensic_data(
                                bin_vector_data,
                                jpeg_trailer_index,
                                IMEI + MD5 + RSA_signature))
                        print("[+] Adding IMEI...", IMEI)
                        print("[+] Adding MD5...", MD5)
                        print("[+] IMobile signature written.")
                        primary_image.close()
                except IOError:
                    msg = "Unable to create file " + primary_image + " on disk"
                    print(msg)
                finally:
                    primary_image.close()
            else:
                print("[-] End Of File not found. Exiting.")
    except FileNotFoundError:
        msg = "Sorry, the file " + temporary_image + " does not exist."
        print(msg)


def signing_RSA(data):
    # Function gets  Mobile's IMEI + JPEG MD5 as string
    # Needs to encode it in bytes
    data = data.encode("utf-8")

    try:
        with open('private.pem', 'r') as f:
            key = RSA.importKey(f.read())
    except IOError as e:
        if e.errno != errno.ENOENT:
            raise
        # If no private key, generates a new one
        key = RSA.generate(2048)
        with open('private.pem', 'wb') as f:
            f.write(key.exportKey('PEM'))
        with open('public.pem', 'wb') as f:
            f.write(key.publickey().exportKey('PEM'))

    # Now function hashes original IMEI + MD5
    hasher = MD5.new(data)

    # And then is signed with private IMobile key
    signer = PKCS1_v1_5.new(key)
    signature = signer.sign(hasher)

    # Gets the hexadecimal representation of the binary data.
    signature = binascii.hexlify(signature)
    # returns byte signature as Unicode string
    return signature.decode("utf-8")


def find_jpeg_last_trailer_index(
        data: bytes) -> int:
    # Finds all 0xFFD9 EOI markers
    EOF_list = [match.start()
                for match in re.finditer(re.escape(b'\xFF\xD9'), data)]
    # And returns the last one
    return EOF_list.pop()


def inject_forensic_data(
        vector: bytes,
        index: int,
        forensic_data: str) -> bytes:
    # vector: JPEG image
    # index: last 0xFFD9 offset
    # forensic_data: IMEI + MD5 + RSA Unicode signature string

    bin_forensic_data = forensic_data.encode()

    # gets the original JPEG data until 0xFFD9
    original_data = vector[:index + len(BIN_TRAILER_EOF)]

    # and returns the original JPEG stamped with
    # forensic data
    return (original_data + bin_forensic_data)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python IMobileJPEG.py <jpeg file>")
    else:
        main()
