# !/usr/bin/python3
# David Arboledas Brihuega
# November 2021
#
# ------------------------------------------------------
# This script is called by extractForensicJPEG to get
# all the forensic data embebed in the jpeg files
# --------------------------------------------------------

# import sys
import binascii
import re
import hashlib
import verifyIMEI
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

TRAILER_EOF = "ffd9"
BIN_TRAILER_NUMBER = binascii.unhexlify(TRAILER_EOF)
IMEI_LENGTH = 15
HASH_LENGTH = 32
#FORENSIC_DATA_LENGTH = IMEI_LENGTH + HASH_LENGTH + RSA_hex_length()

primaryPics = []


def RSA_hex_length():
    try:
        with open('public.pem', 'rb') as f:
            key = RSA.importKey(f.read())
            f.close()
            return key.n.bit_length() / 4 # hex digits length
    except FileNotFoundError:
        msg = (
            "Sorry, Public Key file public.pem does not exist."
            "\nIt can't be verified!")
        print(msg)
        
        
def readingData(file, mode, fileNumber, totalFile):
    # Gets a 'stamped' JPEG file
    temporary_image = file
    # and opens it to read it
    print("\n------ File number", fileNumber, '(', file, ')' "---------")
    try:
        with open(temporary_image, 'rb') as temporary_file:
            bin_vector_data = temporary_file.read()
            print("[ ] Searching for jpeg trailer...")
            # call to find the last 0xFFD9 marker offset
            jpeg_trailer_index = find_jpeg_last_trailer_index(bin_vector_data)
            if jpeg_trailer_index > 0:
                print(
                    "   [+] Found jpeg trailer 0xFFD9 at offset",
                    format(jpeg_trailer_index, ",d"))
                print("[ ] Searching forensic data...")
                # call to read IMEI + original MDhash + RSA signature
                extract_forensic_data(
                    bin_vector_data,
                    jpeg_trailer_index,
                    file,
                    mode,
                    fileNumber,
                    totalFile)
            else:
                print("[-] Trailer 0xFFD9 not found. Exiting.")

    except FileNotFoundError:
        msg = "Sorry, the file " + temporary_image + " does not exist."
        print(msg)


def find_jpeg_last_trailer_index(
        data: bytes) -> int:
    # Finds all 0xFFD9 EOI markers
    try:
        EOF_list = [match.start()
                    for match in re.finditer(re.escape(b'\xFF\xD9'), data)]
        # And returns the offser of the last one
        return EOF_list.pop()
    except IndexError:
        return -1  # Not a JPEG file

# Reading forensic info from file


def extract_forensic_data(
    vector: bytes,
    index: int,
    file: str,
    mode: int,
    fileNumber,
    totalFile
        ):
    # vector: JPEG image
    # index: last 0xFFD9 offset
    forensic_data = vector[index + len(BIN_TRAILER_NUMBER):].decode()
    # IMEI string recorded
    IMEI = forensic_data[:IMEI_LENGTH]
    # MDstring recorded
    MD5_hash = forensic_data[IMEI_LENGTH:IMEI_LENGTH + HASH_LENGTH]
    # JPEG file MD5 until FFD9
    fileMD5 = hashlib.md5(vector[:index + len(BIN_TRAILER_NUMBER)]).hexdigest()

    # RSA signature saved
    RSA_signature = forensic_data[IMEI_LENGTH + HASH_LENGTH:]
    
    FORENSIC_DATA_LENGTH = IMEI_LENGTH + HASH_LENGTH + RSA_hex_length()
    if len(forensic_data) != FORENSIC_DATA_LENGTH:

        if len(forensic_data) == 0:  # There are no data
            print(
                "   [-] Forensic data not found.\n",
                "      Suspected manipulated file...")
            if fileNumber == totalFile and mode == 0:
                writeLogFile(primaryPics)
        else:
            print("   [-] Data NOT VALID, VOID SIGNATURE!")

            try:
                IMEI = int(IMEI)
                if verifyIMEI.isValidIMEI(str(IMEI)):
                    print("   [+] Found possible IMEI: ", IMEI, " --> OK")
                else:
                    print("   [+] Found possible IMEI: ", IMEI, " --> VOID")

            except ValueError:
                print("IMEI edited! Foresnsic data manipulated")

            finally:
                if fileNumber == totalFile and mode == 0:
                    writeLogFile(primaryPics)
    else:  # Forensic data length is OK
        print("   [+] Found IMEI: ", IMEI)
        print("   [+] Found MD5: ", MD5_hash)
        print("   [+] Calculated hash: ", fileMD5)
        print("   [+] Found RSA signature: ", RSA_signature)
        verify_signature(
            IMEI, fileMD5, RSA_signature, MD5_hash, file,
            mode, fileNumber, totalFile)


def verify_signature(
        IMEI, fileMD5, RSA_signature, MD5_hash,
        file, mode, fileNumber, totalFile):
    info = IMEI + fileMD5
    info = info.encode("utf-8")
    # Gets info hash
    hasher = MD5.new(info)
    try:
        with open('public.pem', 'rb') as f:
            key = RSA.importKey(f.read())
            f.close()
            RSA_signature = RSA_signature.encode("utf-8")
            RSA_signature = bytes.fromhex(RSA_signature.decode("utf-8"))
            verifier = PKCS1_v1_5.new(key)
            # Now, verify the signature
            if fileNumber <= totalFile:
                if (
                        verifier.verify(hasher, RSA_signature)
                        and MD5_hash == fileMD5):
                    if mode == 0:
                        print("File:", fileNumber, "Total", totalFile)
                        primaryPics.append(file)
                        print(
                            "\n\t",file, "SIGNATURE is",
                            "VALID. Image NOT edited")
                        if fileNumber == totalFile:
                            writeLogFile(primaryPics)
                        
                    else:  # only one file
                        print(
                            "\n\t",file, "SIGNATURE is",
                            "VALID. Image NOT edited")

                else:  # void signature
                    print(
                        "\n\tINVALID signature!",
                        "The image file was probably edited.")
                    if mode == 0 and fileNumber == totalFile:
                        print("Ultimo fichero", fileNumber, "", totalFile)

    except FileNotFoundError:
        msg = (
            "Sorry, Public Key file public.pem does not exist."
            "\nIt can't be verified!")
        print(msg)


def writeLogFile(primaryPics):
    try:
        file_out = open("primaryImages.log", "w")
        file_out.write("Primary JPEG pictures on dir\n\n")
        for file in primaryPics:
            file_out.write(file + "\n")
        print("\n    [+] File primaryImages.log written...")
    except IOError:
        msg = "Unable to create file primaryImages.log on directory"
        print(msg)
    finally:
        file_out.close()
