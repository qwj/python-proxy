import hashlib, struct, base64

from pproxy.cipher import BaseCipher

# Pure Python Ciphers
ROL = lambda a, b: (a<<b)|((a&0xffffffff)>>(32-b))

class Table_Cipher(BaseCipher):
    LIBRARY = False
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

class StreamCipher(BaseCipher):
    LIBRARY = False
    def setup(self):
        self.stream = self.core()
    def encrypt(self, s):
        return bytes(i^next(self.stream) for i in s)
    decrypt = encrypt

class RC4_Cipher(StreamCipher):
    KEY_LENGTH = 16
    IV_LENGTH = 0
    def core(self):
        data = list(range(256))
        y = 0
        for x in range(256):
            y = (self.key[x % self.KEY_LENGTH] + data[x] + y) & 0xff
            data[x], data[y] = data[y], data[x]
        x = y = 0
        while 1:
            x = (x+1) & 0xff
            y = (y+data[x]) & 0xff
            data[x], data[y] = data[y], data[x]
            yield data[(data[x]+data[y]) & 0xff]

class RC4_MD5_Cipher(RC4_Cipher):
    IV_LENGTH = 16
    def setup(self):
        self.key = hashlib.md5(self.key + self.iv).digest()
        RC4_Cipher.setup(self)

class ChaCha20_Cipher(StreamCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 8
    def core(self):
        data = list(struct.unpack('<16I', b'expand 32-byte k' + self.key + self.iv.rjust(16, b'\x00')))
        ORDERS = ((0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15),(0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)) * 10
        while 1:
            H = data[:]
            for a, b, c, d in ORDERS:
                H[a] += H[b]
                H[d] = ROL(H[d]^H[a], 16)
                H[c] += H[d]
                H[b] = ROL(H[b]^H[c], 12)
                H[a] += H[b]
                H[d] = ROL(H[d]^H[a], 8)
                H[c] += H[d]
                H[b] = ROL(H[b]^H[c], 7)
            yield from struct.pack('<16I', *((a+b)&0xffffffff for a, b in zip(H, data)))
            data[12:14] = (0, data[13]+1) if data[12]==0xffffffff else (data[12]+1, data[13])

class ChaCha20_IETF_Cipher(ChaCha20_Cipher):
    IV_LENGTH = 12

class Salsa20_Cipher(StreamCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 8
    def core(self):
        data = list(struct.unpack('<16I', b'expa' + self.key[:16] + b'nd 3' + self.iv.ljust(16, b'\x00') + b'2-by' + self.key[16:] + b'te k'))
        ORDERS = ((4,0,12,8),(9,5,1,13),(14,10,6,2),(3,15,11,7),(1,0,3,2),(6,5,4,7),(11,10,9,8),(12,15,14,13)) * 10
        while 1:
            H = data[:]
            for a, b, c, d in ORDERS:
                H[a] ^= ROL(H[b]+H[c], 7)
                H[d] ^= ROL(H[a]+H[b], 9)
                H[c] ^= ROL(H[d]+H[a], 13)
                H[b] ^= ROL(H[c]+H[d], 18)
            yield from struct.pack('<16I', *((a+b)&0xffffffff for a, b in zip(H, data)))
            data[8:10] = (0, data[9]+1) if data[8]==0xffffffff else (data[8]+1, data[9])

class CFBCipher(StreamCipher):
    def setup(self):
        self.bit_mode = self.SEGMENT_SIZE % 8 != 0
        self.stream = self.core_bit() if self.bit_mode else self.core()
        self.last = None
        self.cipher = self.CIPHER(self.key)
    def process(self, s, inv=False):
        r = bytearray()
        for i in s:
            if self.bit_mode:
                j = 0
                for k in range(7,-1,-1):
                    ibit = (i>>k)&1
                    jbit = ibit^self.stream.send(self.last)
                    j |= jbit<<k
                    self.last = ibit if inv else jbit
            else:
                j = i^self.stream.send(self.last)
                self.last = i if inv else j
            r.append(j)
        return bytes(r)
    def encrypt(self, s):
        return self.process(s, False)
    def decrypt(self, s):
        return self.process(s, True)
    def core(self):
        next_iv = bytearray(self.iv)
        segment_byte = self.SEGMENT_SIZE // 8
        while 1:
            data = self.cipher.encrypt(next_iv)
            del next_iv[:segment_byte]
            for i in range(segment_byte):
                next_iv.append((yield data[i]))
    def core_bit(self):
        next_iv = int.from_bytes(self.iv, 'big')
        mask = (1 << (self.IV_LENGTH*8)) - 1
        while 1:
            data = self.cipher.encrypt(next_iv.to_bytes(self.IV_LENGTH, 'big'))
            next_iv = (next_iv << self.SEGMENT_SIZE) & mask
            for i in range(self.SEGMENT_SIZE):
                next_iv |= (yield (data[i//8]>>(7-i%8))&1)<<(self.SEGMENT_SIZE-1-i)

class CTRCipher(StreamCipher):
    def setup(self):
        self.stream = self.core()
        self.cipher = self.CIPHER(self.key)
    def encrypt(self, s):
        return bytes(i^next(self.stream) for i in s)
    decrypt = encrypt
    def core(self):
        next_iv = int.from_bytes(self.iv, 'big')
        while 1:
            data = self.cipher.encrypt(next_iv.to_bytes(self.IV_LENGTH, 'big'))
            yield from data
            next_iv = 0 if next_iv >= (1<<(self.IV_LENGTH*8))-1 else next_iv+1

class OFBCipher(StreamCipher):
    def core(self):
        data = self.iv
        while 1:
            data = self.cipher.encrypt(data)
            yield from data

class AES:
    g1 = base64.b64decode(b'Y3x3e/Jrb8UwAWcr/terdsqCyX36WUfwrdSir5ykcsC3/ZMmNj/3zDSl5fFx2DEVBMcjwxiWBZoHEoDi6yeydQmDLBobblqgUjvWsynjL4RT0QDtIPyxW2rLvjlKTFjP0O+q+0NNM4VF+QJ/UDyfqFGjQI+SnTj1vLbaIRD/89LNDBPsX5dEF8Snfj1kXRlzYIFP3CIqkIhG7rgU3l4L2+AyOgpJBiRcwtOsYpGV5HnnyDdtjdVOqWxW9Opleq4IunglLhymtMbo3XQfS72LinA+tWZIA/YOYTVXuYbBHZ7h+JgRadmOlJseh+nOVSjfjKGJDb/mQmhBmS0PsFS7Fg==')
    g2 = [((a<<1)&0xff)^0x1b if a&0x80 else a<<1 for a in g1]
    g3 = [a^(((a<<1)&0xff)^0x1b if a&0x80 else a<<1) for a in g1]
    Rcon = base64.b64decode(b'jQECBAgQIECAGzZs2KtNmi9evGPGlzVq1LN9+u/FkTly5NO9YcKfJUqUM2bMgx06dOjL')
    shifts = tuple((j,j&3|((j>>2)+(j&3))*4&12,(j+3)&3|((j>>2)+((j+3)&3))*4&12,(j+2)&3|((j>>2)+((j+2)&3))*4&12,(j+1)&3|((j>>2)+((j+1)&3))*4&12) for j in range(16))
    def __init__(self, key):
        size = len(key)
        nbr = {16:10, 24:12, 32:14}[size]
        ekey = bytearray(key)
        while len(ekey) < 16*(nbr+1):
            t = ekey[-4:]
            if len(ekey) % size == 0:
                t = [self.g1[i] for i in t[1:]+t[:1]]
                t[0] ^= self.Rcon[len(ekey)//size%51]
            if size == 32 and len(ekey) % size == 16:
                t = [self.g1[i] for i in t]
            for m in t:
                ekey.append(ekey[-size] ^ m)
        self.ekey = tuple(ekey[i*16:i*16+16] for i in range(nbr+1))
    def encrypt(self, data):
        s = [data[j]^self.ekey[0][j] for j in range(16)]
        for key in self.ekey[1:-1]:
            s = [self.g2[s[a]]^self.g1[s[b]]^self.g1[s[c]]^self.g3[s[d]]^key[j] for j,a,b,c,d in self.shifts]
        return bytes(self.g1[s[self.shifts[j][1]]]^self.ekey[-1][j] for j in range(16))

class AES_256_CFB_Cipher(CFBCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 16
    SEGMENT_SIZE = IV_LENGTH*8
    CIPHER = AES

class AES_192_CFB_Cipher(AES_256_CFB_Cipher):
    KEY_LENGTH = 24

class AES_128_CFB_Cipher(AES_256_CFB_Cipher):
    KEY_LENGTH = 16

class AES_256_CFB8_Cipher(AES_256_CFB_Cipher):
    SEGMENT_SIZE = 8

class AES_192_CFB8_Cipher(AES_256_CFB8_Cipher):
    KEY_LENGTH = 24

class AES_128_CFB8_Cipher(AES_256_CFB8_Cipher):
    KEY_LENGTH = 16

class AES_256_CFB1_Cipher(AES_256_CFB_Cipher):
    SEGMENT_SIZE = 1

class AES_192_CFB1_Cipher(AES_256_CFB1_Cipher):
    KEY_LENGTH = 24

class AES_128_CFB1_Cipher(AES_256_CFB1_Cipher):
    KEY_LENGTH = 16

class AES_256_CTR_Cipher(CTRCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 16
    CIPHER = AES

class AES_192_CTR_Cipher(AES_256_CTR_Cipher):
    KEY_LENGTH = 24

class AES_128_CTR_Cipher(AES_256_CTR_Cipher):
    KEY_LENGTH = 16

class AES_256_OFB_Cipher(OFBCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 16
    CIPHER = AES

class AES_192_OFB_Cipher(AES_256_OFB_Cipher):
    KEY_LENGTH = 24

class AES_128_OFB_Cipher(AES_256_OFB_Cipher):
    KEY_LENGTH = 16

class Blowfish:
    P = None
    @staticmethod
    def hex_pi():
        N, n, d = 0, 0, 1
        while 1:
            xn, xd = 120*N**2 + 151*N + 47, 512*N**4 + 1024*N**3 + 712*N**2 + 194*N + 15
            n, d = ((16 * n * xd) + (xn * d)) % (d * xd), d * xd
            yield b'%x' % (16 * n // d)
            N += 1
    def __init__(self, key):
        if not self.P:
            pi = self.hex_pi()
            self.__class__.P = [int(b''.join(next(pi) for j in range(8)), 16) for i in range(18+1024)]
        self.p = [a^b for a, b in zip(self.P[:18], struct.unpack('>18I', (key*(72//len(key)+1))[:72]))]+self.P[18:]
        buf = b'\x00'*8
        for i in range(0, 1042, 2):
            buf = self.encrypt(buf)
            self.p[i:i+2] = struct.unpack('>II', buf)
    def encrypt(self, s):
        Xl, Xr = struct.unpack('>II', s)
        for i in range(16):
            Xl ^= self.p[i]
            y = ((self.p[18+(Xl>>24)]+self.p[274+((Xl>>16)&0xff)])^self.p[530+((Xl>>8)&0xff)])+self.p[786+(Xl&0xff)]
            Xl, Xr = (Xr ^ y) & 0xffffffff, Xl
        return struct.pack('>II', Xr^self.p[17], Xl^self.p[16])

class BF_CFB_Cipher(CFBCipher):
    KEY_LENGTH = 16
    IV_LENGTH = 8
    SEGMENT_SIZE = IV_LENGTH*8
    CIPHER = Blowfish

MAP = {name[:-7].replace('_', '-').lower()+'-py': cls for name, cls in globals().items() if name.endswith('_Cipher')}

