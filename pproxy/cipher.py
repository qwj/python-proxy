import os, hashlib, hmac

class BaseCipher(object):
    PYTHON = False
    CACHE = {}
    def __init__(self, key, ota=False, setup_key=True):
        if self.KEY_LENGTH > 0 and setup_key:
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
        return self
    def decrypt(self, s):
        return self.cipher.decrypt(s)
    def encrypt(self, s):
        return self.cipher.encrypt(s)
    @classmethod
    def name(cls):
        return cls.__name__.replace('_Cipher', '').replace('_', '-').lower()

class AEADCipher(BaseCipher):
    PACKET_LIMIT = 16*1024-1
    def setup_iv(self, iv=None):
        self.iv = os.urandom(self.IV_LENGTH) if iv is None else iv
        randkey = hmac.new(self.iv, self.key, hashlib.sha1).digest()
        blocks_needed = (self.KEY_LENGTH + len(randkey) - 1) // len(randkey)
        okm = bytearray()
        output_block = b''
        for counter in range(blocks_needed):
            output_block = hmac.new(randkey, output_block + b'ss-subkey' + bytes([counter+1]), hashlib.sha1).digest()
            okm.extend(output_block)
        self.key = bytes(okm[:self.KEY_LENGTH])
        self._nonce = 0
        self._buffer = bytearray()
        self._declen = None
        self.setup()
    @property
    def nonce(self):
        ret = self._nonce.to_bytes(self.NONCE_LENGTH, 'little')
        self._nonce = (self._nonce+1) & ((1<<self.NONCE_LENGTH)-1)
        return ret
    def decrypt(self, s):
        self._buffer.extend(s)
        ret = bytearray()
        try:
            while 1:
                if self._declen is None:
                    if len(self._buffer) < 2+self.TAG_LENGTH:
                        break
                    self._declen = int.from_bytes(self.decrypt_and_verify(self._buffer[:2], self._buffer[2:2+self.TAG_LENGTH]), 'big')
                    assert self._declen <= self.PACKET_LIMIT
                    del self._buffer[:2+self.TAG_LENGTH]
                else:
                    if len(self._buffer) < self._declen+self.TAG_LENGTH:
                        break
                    ret.extend(self.decrypt_and_verify(self._buffer[:self._declen], self._buffer[self._declen:self._declen+self.TAG_LENGTH]))
                    del self._buffer[:self._declen+self.TAG_LENGTH]
                    self._declen = None
        except Exception:
            return bytes([0])
        return bytes(ret)
    def encrypt(self, s):
        ret = bytearray()
        for i in range(0, len(s), self.PACKET_LIMIT):
            buf = s[i:i+self.PACKET_LIMIT]
            len_chunk, len_tag = self.encrypt_and_digest(len(buf).to_bytes(2, 'big'))
            body_chunk, body_tag = self.encrypt_and_digest(buf)
            ret.extend(len_chunk+len_tag+body_chunk+body_tag)
        return bytes(ret)

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
class ChaCha20_IETF_Cipher(ChaCha20_Cipher):
    IV_LENGTH = 12

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

class AES_256_CTR_Cipher(BaseCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 16
    def setup(self):
        from Crypto.Cipher import AES
        self.cipher = AES.new(self.key, AES.MODE_CTR, nonce=b'', initial_value=self.iv)
class AES_192_CTR_Cipher(AES_256_CTR_Cipher):
    KEY_LENGTH = 24
class AES_128_CTR_Cipher(AES_256_CTR_Cipher):
    KEY_LENGTH = 16

class AES_256_GCM_Cipher(AEADCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 32
    NONCE_LENGTH = 12
    TAG_LENGTH = 16
    def decrypt_and_verify(self, buffer, tag):
        return self.cipher_new(self.nonce).decrypt_and_verify(buffer, tag)
    def encrypt_and_digest(self, buffer):
        return self.cipher_new(self.nonce).encrypt_and_digest(buffer)
    def setup(self):
        from Crypto.Cipher import AES
        self.cipher_new = lambda nonce: AES.new(self.key, AES.MODE_GCM, nonce=nonce, mac_len=self.TAG_LENGTH)
class AES_192_GCM_Cipher(AES_256_GCM_Cipher):
    KEY_LENGTH = IV_LENGTH = 24
class AES_128_GCM_Cipher(AES_256_GCM_Cipher):
    KEY_LENGTH = IV_LENGTH = 16

class ChaCha20_IETF_POLY1305_Cipher(AEADCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 32
    NONCE_LENGTH = 12
    TAG_LENGTH = 16
    def decrypt_and_verify(self, buffer, tag):
        return self.cipher_new(self.nonce).decrypt_and_verify(buffer, tag)
    def encrypt_and_digest(self, buffer):
        return self.cipher_new(self.nonce).encrypt_and_digest(buffer)
    def setup(self):
        from Crypto.Cipher import ChaCha20_Poly1305
        self.cipher_new = lambda nonce: ChaCha20_Poly1305.new(key=self.key, nonce=nonce)

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

class PacketCipher:
    def __init__(self, cipher, key, name):
        self.cipher = lambda iv=None: cipher(key).setup_iv(iv)
        self.ivlen = cipher.IV_LENGTH
        self.name = name
    def decrypt(self, data):
        return self.cipher(data[:self.ivlen]).decrypt(data[self.ivlen:])
    def encrypt(self, data):
        cipher = self.cipher()
        return cipher.iv+cipher.encrypt(data)

MAP = {cls.name(): cls for name, cls in globals().items() if name.endswith('_Cipher')}

def get_cipher(cipher_key):
    from .cipherpy import MAP as MAP_PY
    cipher, key = cipher_key.split(':')
    cipher_name, ota, _ = cipher.partition('!')
    if cipher_name not in MAP and cipher_name not in MAP_PY and not (cipher_name.endswith('-py') and cipher_name[:-3] in MAP_PY):
        return f'existing ciphers: {sorted(set(MAP)|set(MAP_PY))}', None
    key, ota = key.encode(), bool(ota) if ota else False
    cipher = MAP.get(cipher_name)
    if cipher:
        try:
            assert __import__('Crypto').version_info >= (3, 4)
        except Exception:
            cipher = None
    if cipher is None:
        cipher = MAP_PY.get(cipher_name)
        if cipher is None and cipher_name.endswith('-py'):
            cipher_name = cipher_name[:-3]
            cipher = MAP_PY.get(cipher_name)
    if cipher is None:
        return 'this cipher needs library: "pip3 install pycryptodome"', None
    cipher_name += ('-py' if cipher.PYTHON else '')
    def apply_cipher(reader, writer, pdecrypt, pdecrypt2, pencrypt, pencrypt2):
        reader_cipher, writer_cipher = cipher(key, ota=ota), cipher(key, ota=ota)
        reader_cipher._buffer = b''
        def decrypt(s):
            s = pdecrypt2(s)
            if not reader_cipher.iv:
                s = reader_cipher._buffer + s
                if len(s) >= reader_cipher.IV_LENGTH:
                    reader_cipher.setup_iv(s[:reader_cipher.IV_LENGTH])
                    return pdecrypt(reader_cipher.decrypt(s[reader_cipher.IV_LENGTH:]))
                else:
                    reader_cipher._buffer = s
                    return b''
            else:
                return pdecrypt(reader_cipher.decrypt(s))
        if hasattr(reader, 'decrypts'):
            reader.decrypts.append(decrypt)
        else:
            reader.decrypts = [decrypt]
            def feed_data(s, o=reader.feed_data, p=reader.decrypts):
                for decrypt in p:
                    s = decrypt(s)
                    if not s:
                        return
                o(s)
            reader.feed_data = feed_data
            if reader._buffer:
                reader._buffer, buf = bytearray(), reader._buffer
                feed_data(buf)
        def write(s, o=writer.write):
            if not writer_cipher.iv:
                writer_cipher.setup_iv()
                o(pencrypt2(writer_cipher.iv))
            if not s:
                return
            return o(pencrypt2(writer_cipher.encrypt(pencrypt(s))))
        writer.write = write
        return reader_cipher, writer_cipher
    apply_cipher.cipher = cipher
    apply_cipher.key = key
    apply_cipher.name = cipher_name
    apply_cipher.ota = ota
    apply_cipher.plugins = []
    apply_cipher.datagram = PacketCipher(cipher, key, cipher_name)
    return None, apply_cipher

