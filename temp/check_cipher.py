import hashlib, binascii
from passlib.utils.pbkdf2 import pbkdf1
import subprocess

def hasher(algo, data):
    hashes = {'md5': hashlib.md5, 'sha256': hashlib.sha256, 'sha512': hashlib.sha512}
    # print('data:' + binascii.hexlify(data).decode('ascii').upper())
    h = hashes[algo]()
    h.update(data)

    return h.digest()

# pwd and salt must be bytes objects
def openssl_kdf(algo, pwd, salt, key_size, iv_size):
    if algo == 'md5':
        temp = pbkdf1(pwd, salt, 1, 16, 'md5')
    else:
        temp = b''

    fd = temp    

    while len(fd) < key_size + iv_size:
        con=temp + pwd + salt
        temp = hasher(algo, con)
        print('temp:' + binascii.hexlify(temp).decode('ascii').upper())
        print('con :'+con)
        fd += temp

    key = fd[0:key_size]
    iv = fd[key_size:key_size+iv_size]

    print('salt=' + binascii.hexlify(salt).decode('ascii').upper())
    print('key=' + binascii.hexlify(key).decode('ascii').upper())
    print('iv=' + binascii.hexlify(iv).decode('ascii').upper())

    return key, iv

openssl_kdf('sha256', b'MYPASSWORD', b'\xA6\x8D\x6E\x40\x6A\x08\x7F\x05', 32, 16)
# subprocess.Popen(['openssl', 'enc', '-aes-256-cbc', '-P', '-pass', 'pass:MYPASSWORD', '-S', 'A68D6E406A087F05', '-md', 'SHA256'])
#

