from Crypto.Cipher import AES
import base64
import hashlib

def sha256(MainKey):
    sha256 = hashlib.sha256()
    sha256.update(MainKey.encode('utf-8'))    
    res = sha256.digest()
    return res

def md5(MainKey):
    md5 = hashlib.md5()
    md5.update(MainKey.encode('utf-8'))    
    res2 = md5.digest()
    return res2

def pkcs7padding(text):

    bs = AES.block_size 
    length = len(text)
    bytes_length = len(bytes(text, encoding='utf-8'))


    padding_size = length if(bytes_length == length) else bytes_length
    padding = bs - padding_size % bs

    
    padding_text = chr(padding) * padding
    return text + padding_text

def aes_encrypt_v2(content, key, iv):

    key = sha256(MainKey)
    iv = md5(MainKey)

    aes = AES.new(key, AES.MODE_CBC, iv)

    content_padding = pkcs7padding(content)

    encrypt_bytes = aes.encrypt(bytes(content_padding, encoding='utf-8'))

    result = str(base64.b64encode(encrypt_bytes), encoding='utf-8')
    return result

MainKey = '475b40c0-2c9c-4082-9403-fba2c1a1d70f'
ac = input('請輸入帳號: ')
pw = input('請輸入密碼: ')
key = sha256(MainKey)
iv = md5(MainKey)
print(aes_encrypt_v2(ac, key, iv))
print(aes_encrypt_v2(pw, key, iv))

