import os, hashlib

class BaseCipher(object):
    PYTHON = False
    CACHE = {}
    def __init__(self, key, ota=False):
        if self.KEY_LENGTH > 0:
            self.key = self.CACHE.get(b'key'+key)
            if self.key is None:
                keybuf = []
                while len(b''.join(keybuf)) < self.KEY_LENGTH:
                    keybuf.append(hashlib.md5((keybuf[-1] if keybuf else b'') + key).digest())
                self.key = self.CACHE[b'key'+key] = b''.join(keybuf)[:self.KEY_LENGTH]
        else:
            self.key = key
        self.ota = ota
        self.iv = None
    def setup_iv(self, iv=None):
        self.iv = os.urandom(self.IV_LENGTH) if iv is None else iv
        self.setup()
    def decrypt(self, s):
        return self.cipher.decrypt(s)
    def encrypt(self, s):
        return self.cipher.encrypt(s)
    @classmethod
    def name(cls):
        return cls.__name__.replace('_Cipher', '').replace('_', '-').lower()

class RC4_Cipher(BaseCipher):
    KEY_LENGTH = 16
    IV_LENGTH = 0
    def setup(self):
        from Crypto.Cipher import ARC4
        self.cipher = ARC4.new(self.key)

class RC4_MD5_Cipher(RC4_Cipher):
    IV_LENGTH = 16
    def setup(self):
        self.key = hashlib.md5(self.key + self.iv).digest()
        RC4_Cipher.setup(self)

class ChaCha20_Cipher(BaseCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 8
    def setup(self):
        from Crypto.Cipher import ChaCha20
        self.cipher = ChaCha20.new(key=self.key, nonce=self.iv)

class Salsa20_Cipher(BaseCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 8
    def setup(self):
        from Crypto.Cipher import Salsa20
        self.cipher = Salsa20.new(key=self.key, nonce=self.iv)

class AES_256_CFB_Cipher(BaseCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 16
    SEGMENT_SIZE = 128
    def setup(self):
        from Crypto.Cipher import AES
        self.cipher = AES.new(self.key, AES.MODE_CFB, iv=self.iv, segment_size=self.SEGMENT_SIZE)

class AES_128_CFB_Cipher(AES_256_CFB_Cipher):
    KEY_LENGTH = 16

class AES_192_CFB_Cipher(AES_256_CFB_Cipher):
    KEY_LENGTH = 24

class AES_256_CFB8_Cipher(AES_256_CFB_Cipher):
    SEGMENT_SIZE = 8

class AES_192_CFB8_Cipher(AES_256_CFB8_Cipher):
    KEY_LENGTH = 24

class AES_128_CFB8_Cipher(AES_256_CFB8_Cipher):
    KEY_LENGTH = 16

class AES_256_OFB_Cipher(BaseCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 16
    def setup(self):
        from Crypto.Cipher import AES
        self.cipher = AES.new(self.key, AES.MODE_OFB, iv=self.iv)

class AES_192_OFB_Cipher(AES_256_OFB_Cipher):
    KEY_LENGTH = 24

class AES_128_OFB_Cipher(AES_256_OFB_Cipher):
    KEY_LENGTH = 16

class BF_CFB_Cipher(BaseCipher):
    KEY_LENGTH = 16
    IV_LENGTH = 8
    def setup(self):
        from Crypto.Cipher import Blowfish
        self.cipher = Blowfish.new(self.key, Blowfish.MODE_CFB, iv=self.iv, segment_size=64)

class CAST5_CFB_Cipher(BaseCipher):
    KEY_LENGTH = 16
    IV_LENGTH = 8
    def setup(self):
        from Crypto.Cipher import CAST
        self.cipher = CAST.new(self.key, CAST.MODE_CFB, iv=self.iv, segment_size=64)

class DES_CFB_Cipher(BaseCipher):
    KEY_LENGTH = 8
    IV_LENGTH = 8
    def setup(self):
        from Crypto.Cipher import DES
        self.cipher = DES.new(self.key, DES.MODE_CFB, iv=self.iv, segment_size=64)

MAP = {cls.name(): cls for name, cls in globals().items() if name.endswith('_Cipher')}

def get_cipher(cipher_key):
    from pproxy.cipherpy import MAP as MAP_PY
    cipher, _, key = cipher_key.partition(':')
    cipher_name, ota, _ = cipher.partition('!')
    if not key:
        return 'empty key', None
    if cipher_name not in MAP and cipher_name not in MAP_PY:
        return 'existing ciphers: {}'.format(sorted(set(MAP)|set(MAP_PY))), None
    key, ota = key.encode(), bool(ota) if ota else False
    cipher = MAP.get(cipher_name)
    if cipher:
        try:
            assert __import__('Crypto').version_info >= (3, 4)
        except Exception:
            cipher = None
    if cipher is None:
        cipher = MAP_PY.get(cipher_name)
    if cipher is None:
        return 'this cipher needs library: "pip3 install pycryptodome"', None
    def apply_cipher(reader, writer):
        reader_cipher, writer_cipher = cipher(key, ota=ota), cipher(key, ota=ota)
        reader_cipher._buffer = b''
        def feed_data(s, o=reader.feed_data):
            if not reader_cipher.iv:
                s = reader_cipher._buffer + s
                if len(s) >= reader_cipher.IV_LENGTH:
                    reader_cipher.setup_iv(s[:reader_cipher.IV_LENGTH])
                    o(reader_cipher.decrypt(s[reader_cipher.IV_LENGTH:]))
                else:
                    reader_cipher._buffer = s
            else:
                o(reader_cipher.decrypt(s))
        def write(s, o=writer.write):
            if not s:
                return
            if not writer_cipher.iv:
                writer_cipher.setup_iv()
                o(writer_cipher.iv)
            return o(writer_cipher.encrypt(s))
        reader.feed_data = feed_data
        writer.write = write
        if reader._buffer:
            reader._buffer, buf = bytearray(), reader._buffer
            feed_data(buf)
        return reader_cipher, writer_cipher
    apply_cipher.name = cipher_name + ('-py' if cipher.PYTHON else '')
    apply_cipher.ota = ota
    return None, apply_cipher

