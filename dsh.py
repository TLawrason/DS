import socket
import sys
import struct
import json
from base64 import b64encode,b64decode
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from Crypto.Hash import SHA3_512
from Crypto.Signature import PKCS1_v1_5

def hash(a,b):
    ha = SHA3_512.new(a).hexdigest()
    hb = SHA3_512.new(b).hexdigest()
    return SHA3_512.new(b64decode(ha+hb))

def sign(key,data):
    return PKCS1_v1_5.new(key).sign(data)

def verify(key,hash,signature):
    return PKCS1_v1_5.new(key).verify(hash,signature)

def MD(I1,I2,mpu_key,bpu_key,cpu_key,cpr_key):
    sb = encryptor(I1,mpu_key)
    sc = encryptor(I2,bpu_key)
    md = hash(sb,sc)
    ds = sign(cpr_key,md)
    return (ds.decode('latin-1'),sb.decode(),sc.decode())

def encryptor(msg,pu_key):
    E = PKCS1_OAEP.new(pu_key)
    E_msg = E.encrypt(msg)
    encoded_E_msg = b64encode(E_msg)
    return encoded_E_msg

def receipt(msg,s_key,e_key):
    R_enc = encryptor(msg,e_key)
    R_hash = SHA3_512.new(R_enc)
    R_signed = sign(s_key,R_hash)
    return (R_signed.decode('latin-1'),R_enc.decode())

def receipt_verifier(R,s_key,pr_key):
    R_signed, R_enc = R
    R_signed = R_signed.encode('latin-1')
    R_enc = R_enc.encode()
    R_hash = SHA3_512.new(R_enc)
    R_ver = verify(s_key,R_hash,R_signed)
    if R_ver: return decryptor(R_enc,pr_key),R_ver
    else: return b'Reciept Could Not Be Verified Closing Connection',R_ver

def decryptor(encoded_E_msg, pr_key):
    D = PKCS1_OAEP.new(pr_key)
    decoded_E_msg = b64decode(encoded_E_msg)
    decoded_D_msg = D.decrypt(decoded_E_msg)
    return decoded_D_msg

def key_pair_generation():
    private_key = RSA.generate(2048)
    pubkey = private_key.publickey()
    return private_key,pubkey

def receive(channel):
    size = channel.recv(struct.calcsize("i"))
    if len(size) == 0: 
        return 0,0,0
    size = struct.unpack("i", size)[0]
    data = ""
    while len(data) < size:
        msg = channel.recv(size - len(data))
        if not msg:
            return None
        data += msg.decode('utf-8')
    return json.loads(data.strip())

def send(channel,md):
    md = json.dumps(md)
    channel.send(struct.pack("i", len(md)) + md.encode('utf-8'))