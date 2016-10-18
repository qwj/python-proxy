import os, hashlib, struct, functools, argparse, hmac

#pip3 install pycryptodome
from Crypto.Cipher import ARC4, ChaCha20, Salsa20, AES, DES, CAST, Blowfish, ARC2

class BaseCipher(object):
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
    def patch_ota_reader(self, reader):
        chunk_id = 0
        async def patched_read():
            nonlocal chunk_id
            try:
                data_len = int.from_bytes(await reader.readexactly(2), 'big')
            except Exception:
                return None
            checksum = await reader.readexactly(10)
            data = await reader.readexactly(data_len)
            checksum_server = hmac.new(self.iv+chunk_id.to_bytes(4, 'big'), data, 'sha1').digest()
            assert checksum_server[:10] == checksum
            chunk_id += 1
            return data
        reader.read_ = patched_read
    def patch_ota_writer(self, writer):
        chunk_id = 0
        write = writer.write
        def patched_write(data):
            nonlocal chunk_id
            if not data: return
            checksum = hmac.new(self.iv+chunk_id.to_bytes(4, 'big'), data, 'sha1').digest()
            chunk_id += 1
            return write(len(data).to_bytes(2, 'big') + checksum[:10] + data)
        writer.write = patched_write

class TableCipher(BaseCipher):
    KEY_LENGTH = 0
    IV_LENGTH = 0
    def setup(self):
        if self.key in self.CACHE:
            self.encrypt_table, self.decrypt_table = self.CACHE[self.key]
        else:
            a, _ = struct.unpack('<QQ', hashlib.md5(self.key).digest())
            table = list(range(256))
            for i in range(1, 1024):
                table.sort(key = lambda x: a % (x + i))
            self.encrypt_table = bytes(table)
            self.decrypt_table = bytes.maketrans(self.encrypt_table, bytes(range(256)))
            self.CACHE[self.key] = self.encrypt_table, self.decrypt_table
    def decrypt(self, s):
        return bytes.translate(s, self.decrypt_table)
    def encrypt(self, s):
        return bytes.translate(s, self.encrypt_table)

class RC4Cipher(BaseCipher):
    KEY_LENGTH = 16
    IV_LENGTH = 0
    def setup(self):
        self.cipher = ARC4.new(self.key)

class RC4MD5Cipher(BaseCipher):
    KEY_LENGTH = 16
    IV_LENGTH = 16
    def setup(self):
        self.cipher = ARC4.new(hashlib.md5(self.key + self.iv).digest())

class ChaCha20Cipher(BaseCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 8
    def setup(self):
        self.cipher = ChaCha20.new(key=self.key, nonce=self.iv)

class Salsa20Cipher(BaseCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 8
    def setup(self):
        self.cipher = Salsa20.new(key=self.key, nonce=self.iv)

class AES256CFBCipher(BaseCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 16
    def setup(self):
        self.cipher = AES.new(self.key, AES.MODE_CFB, iv=self.iv, segment_size=128)

class AES128CFBCipher(AES256CFBCipher):
    KEY_LENGTH = 16

class AES192CFBCipher(AES256CFBCipher):
    KEY_LENGTH = 24

class BFCFBCipher(BaseCipher):
    KEY_LENGTH = 16
    IV_LENGTH = 8
    def setup(self):
        self.cipher = Blowfish.new(self.key, Blowfish.MODE_CFB, iv=self.iv, segment_size=64)

class CAST5CFBCipher(BaseCipher):
    KEY_LENGTH = 16
    IV_LENGTH = 8
    def setup(self):
        self.cipher = CAST.new(self.key, CAST.MODE_CFB, iv=self.iv, segment_size=64)

class DESCFBCipher(BaseCipher):
    KEY_LENGTH = 8
    IV_LENGTH = 8
    def setup(self):
        self.cipher = DES.new(self.key, DES.MODE_CFB, iv=self.iv, segment_size=64)

MAPPINGS = {\
    'table': TableCipher,
    'rc4': RC4Cipher,
    'rc4-md5': RC4MD5Cipher,
    'chacha20': ChaCha20Cipher,
    'salsa20': Salsa20Cipher,
    'aes-128-cfb': AES128CFBCipher,
    'aes-192-cfb': AES192CFBCipher,
    'aes-256-cfb': AES256CFBCipher,
    'bf-cfb': BFCFBCipher,
    'cast5-cfb': CAST5CFBCipher,
    'des-cfb': DESCFBCipher,
}

def get_cipher(cipher_key):
    cipher, _, key = cipher_key.partition(':')
    cipher, ota, _ = cipher.partition('!')
    if not key:
        raise argparse.ArgumentTypeError('empty key')
    if cipher not in MAPPINGS:
        raise argparse.ArgumentTypeError(f'existing ciphers: {list(MAPPINGS.keys())}')
    cipher, key, ota = MAPPINGS[cipher], key.encode(), bool(ota) if ota else False
    def apply_cipher(reader, writer):
        reader_cipher, writer_cipher = cipher(key, ota=ota), cipher(key, ota=ota)
        def feed_data(s, o=reader.feed_data):
            if not reader_cipher.iv:
                s = bytes(reader._buffer + s)
                if len(s) >= reader_cipher.IV_LENGTH:
                    reader_cipher.setup_iv(s[:reader_cipher.IV_LENGTH])
                    s = reader_cipher.decrypt(s[reader_cipher.IV_LENGTH:])
                    reader._buffer.clear()
            else:
                s = reader_cipher.decrypt(s)
            return o(s)
        def write(s, o=writer.write):
            if not s:
                return
            if not writer_cipher.iv:
                writer_cipher.setup_iv()
                o(writer_cipher.iv)
            return o(writer_cipher.encrypt(s))
        reader.feed_data = feed_data
        writer.write = write
        return reader_cipher, writer_cipher
    apply_cipher.ota = ota
    return apply_cipher

