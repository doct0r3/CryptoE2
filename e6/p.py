from collections import OrderedDict
from Crypto.Cipher import AES
from Crypto import Random
import re

USER_DB = OrderedDict()
user_cnt = 0
KEY = Random.new().read(16)

class objectify:

    def __init__(self, cookie):
        self.cookie = cookie
        self.obj = OrderedDict()

    def convert(self):
        if len(self.obj) > 0:
            return self.obj

        # get key=value pairs
        kv = self.cookie.split('&')
        # assign key=value pairs to dictionary: dict[key]=value
        for pair in kv:
            k, v = pair.split('=')
            self.obj[k] = v
        return self.obj

    def __repr__(self):

        self.convert()
        ret_value = "{\n"
        last_key = next(reversed(self.obj))
        for key, value in self.obj.items():
            if not key == last_key:
                ret_value += f"\t{ key }: '{ value }',\n"
            else:
                ret_value += f"\t{ key }: '{ value }'\n"
        ret_value += "}"
        return ret_value

def pad(value, size):
    if len(value) % size == 0:
        return value
    padding = size - len(value) % size
    padValue = bytes([padding]) * padding
    return value + padValue

def profile_for(user_info):
    # get cookie from user_info
    global user_cnt
    user_info = re.sub("&|=", "", user_info) # sanitize the `user_info` to remove '&' and '=' signs
    cookie = f"email={ user_info }&uid={ user_cnt }&role=user"
    user_cnt += 1

    # encrypt the encoded cookie-info
    paddedCookie = pad(bytes(cookie, 'ascii'), AES.block_size) # PKCS#7 padding 
    ecb = AES.new(KEY, AES.MODE_ECB)
    cipherCookie = ecb.encrypt(paddedCookie)

    return cipherCookie

def decrypt_profile(key, cipherCookie):
    # decrypt the `cipherCookie`
    ecb = AES.new(key, AES.MODE_ECB)
    plainCookie = ecb.decrypt(cipherCookie)

    # remove PKCS#7 padding
    last_byte = plainCookie[-1]
    # padding is a numeral whose value ranges from 0 to block_size - 1
    if last_byte in range(AES.block_size - 1):
        padding = bytes([last_byte]) * last_byte
        # check if the `last_byte` number of bytes are the padding bytes
        if plainCookie[-last_byte:] == padding:
            plainCookie = plainCookie[:-plainCookie[-1]]
    
    # parse cookie to object format
    cookie = plainCookie.decode('ascii')
    obj = objectify(cookie) 
    return cookie, str(obj)

def create_admin_profile():
    cookie_parts = 'email=@gmail.com&uid=2&role='
    username = 'A' * (AES.block_size - len(cookie_parts) % AES.block_size)
    email = username + "@gmail.com"
    cipherCookie1 = profile_for(email)
    cookie_param = "email="
    hacker_mail = 'A' * (AES.block_size - len(cookie_param) % AES.block_size)
    value = pad(b'admin', AES.block_size).decode('ascii')
    hacker_mail += value
    cipherCookie2 = profile_for(hacker_mail)

    # all except the last block of `cipherCookie1` i.e., `email=***@gmail.com&uid=0&role=`
    block1 = cipherCookie1[:-AES.block_size]
    # just the block containing `admin`, here it is the second block 
    block2 = cipherCookie2[AES.block_size:AES.block_size*2]
    # concatenate `block1` and `block2`
    cipherBlock = block1 + block2 

    cookie, obj = decrypt_profile(KEY, cipherBlock)
    print(f"Cookie Created: { cookie }")
    print(f"Object Created: { obj }")

if __name__ == "__main__":
    create_admin_profile()