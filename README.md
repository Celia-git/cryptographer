# Cryptographer
Encrypt and decrypt text files (txt, csv, etc) with a personal password

- download and open zip folder
- deposit text files you want encrypted into the **cryptographer/decoded/** folder
  ## Windows terminal directions
- in terminal, navigate to **cryptographer/** folder
- run `pip install -r requirements.txt`
- run the program with the command: `python encrypt_file.py [arg1]` <br /> &ensp; where arg1 is:<br /> &emsp; e (for encode: unencrypted txt files are placed in **decoded/**) or <br /> &emsp; d (for decode: encrypted and salt txt files are placed in **encoded/**)
- program will prompt for password, user enters password without echoing
  ### If running encode: 
- program will encrypt the text files,
- place encrypted files and salt files in **encoded/**,
- then delete original files in **decoded/**
  ### If running decode:
- program will decrypt the text files,
- place unencrypted files in **decoded/*
- then delete the encrypted files and salt files in **encoded/** 
