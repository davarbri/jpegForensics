# !/usr/bin/python3
# David Arboledas Brihuega
# November 2021
# usage: python extractForensicJPEG.py < file or dir >
# ------------------------------------------------------
# The script checks whether a JPEG file is edited or
# not and verifies if the IMEI of the mobile phone is correct.
# --------------------------------------------------------

import os
import sys
import extraction


def main():
    totalFile = 0
    fileNumber = 0
    extraction.numberFile = 0
    dir = sys.argv[1]
    head, tail = os.path.split(dir)

    try:  # Is a directory
        content = os.listdir(dir)
        # Gets a list with all JPEG files on dir
        JPEG_pics = []
        for file in content:
            if (
                os.path.isfile(os.path.join(dir, file)) and
                (file.endswith('.jpg') or file.endswith('.JPG'))
            ):
                print("file ", dir + '\\'+file)
                JPEG_pics.append(file)
                totalFile += 1  # Number of JPEG files on dir
        # Calls extraction.py with every JPEG file recursively
        for file in JPEG_pics:
            fileNumber += 1
            extraction.readingData(
                dir + '\\'+file, 0, fileNumber, totalFile)  # 0 mode means directory

    except NotADirectoryError:  # Is a file
        fileName = tail
        #print("Fichero ", dir)
        extraction.readingData(
            head + '\\'+ tail, mode=1,
            fileNumber=1,
            totalFile=1)  # 1 means only a file


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("\n\tUSAGE: python extractForensicJPEG.py <file or path dir>")
    else:
        main()
