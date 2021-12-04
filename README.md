# jpegForensics
DIGITAL IMAGE FORENSICS

David Arboledas Brihuega, 2021

--------------------------------------------------------------------
REQUIREMENT
1. Python 3.8 for windows
2. Python libraries:
   * PyCryptodome 3.11.0

Simply run the next command to install the library:
    pip install pycryptodome

--------------------------------------------------------------------
SCRIPTS
##########
1. Creating the 2048-bit RSA key pair

python RSA_keys.py

After you run the command, you will then have two files
(private.pem, public.pem) with the RSA key pair in PEM format


##########
2. Adding the forensic information to a jpeg file

python IMobileJPEG.py <jpeg_file>

After you run the command, the IMEI, jpeg MD5 hash
and the RSA signature will be added to the end of the file.


##########
3. Verifying the integrity of the file and its digital origin 

python extractForensicJPEG.py <jpeg_file or directory>

The script extractForensicJPEG.py needs the following ones:
   extraction.py
   verifyIMEI.py

After you run the command, the whole information about each file 
will be displayed on the screen. In addition, a file named primaryImages.log 
containing the names of the primary (unmodified) images will be created.

##########


----------------------------------------------------------------
For more information about the theory, you can check the 
author's Master's thesis: "Forensic Analysis: A New Analytical 
Model For Digital Image Authentication"
---------------------------------------------------------------

COMMANDS SUMMARY
python RSA_keys.py
python IMobileJPEG.py <jpeg_file>
python extractForensicJPEG.py <jpeg_file or directory>
