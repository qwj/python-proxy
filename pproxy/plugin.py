import datetime, zlib, os, binascii, hmac, hashlib, time, random, collections

packstr = lambda s, n=2: len(s).to_bytes(n, 'big') + s
toint = lambda s, o='big': int.from_bytes(s, o)

class BasePlugin(object):
    async def init_client_data(self, reader, writer, cipher):
        pass
    async def init_server_data(self, reader, writer, cipher, raddr):
        pass
    def add_cipher(self, cipher):
        pass
    @classmethod
    def name(cls):
        return cls.__name__.replace('_Plugin', '').replace('__', '.').lower()

class Plain_Plugin(BasePlugin):
    pass

class Origin_Plugin(BasePlugin):
    pass

class Http_Simple_Plugin(BasePlugin):
    async def init_client_data(self, reader, writer, cipher):
        buf = await reader.read_until(b'\r\n\r\n')
        data = buf.split(b' ')[:2]
        data = bytes.fromhex(data[1][1:].replace(b'%',b'').decode())
        reader._buffer[0:0] = data
        writer.write(b'HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Encoding: gzip\r\nContent-Type: text/html\r\nDate: ' + datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT').encode() + b'\r\nServer: nginx\r\nVary: Accept-Encoding\r\n\r\n')
    async def init_server_data(self, reader, writer, cipher, raddr):
        writer.write(f'GET / HTTP/1.1\r\nHost: {raddr}\r\nUser-Agent: curl\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\n\r\n'.encode())
        await reader.read_until(b'\r\n\r\n')

TIMESTAMP_TOLERANCE = 5 * 60

class Tls1__2_Ticket_Auth_Plugin(BasePlugin):
    CACHE = collections.deque(maxlen = 100)
    async def init_client_data(self, reader, writer, cipher):
        key = cipher.cipher(cipher.key).key
        assert await reader.read_n(3) == b'\x16\x03\x01'
        header = await reader.read_n(toint(await reader.read_n(2)))
        assert header[:2] == b'\x01\x00'
        assert header[4:6] == b'\x03\x03'
        cacheid = header[6:28]
        sessionid = header[39:39+header[38]]
        assert cacheid not in self.CACHE
        self.CACHE.append(cacheid)
        utc_time = int(time.time())
        assert hmac.new(key+sessionid, cacheid, hashlib.sha1).digest()[:10] == header[28:38]
        assert abs(toint(header[6:10]) - utc_time) < TIMESTAMP_TOLERANCE
        addhmac = lambda s: s + hmac.new(key+sessionid, s, hashlib.sha1).digest()[:10]
        writer.write(addhmac((b"\x16\x03\x03" + packstr(b"\x02\x00" + packstr(b'\x03\x03' + addhmac(utc_time.to_bytes(4, 'big') + os.urandom(18)) + b'\x20' + sessionid + b'\xc0\x2f\x00\x00\x05\xff\x01\x00\x01\x00')) + (b"\x16\x03\x03" + packstr(b"\x04\x00" + packstr(os.urandom(random.randrange(164)*2+64))) if random.randint(0, 8) < 1 else b'') + b"\x14\x03\x03\x00\x01\x01\x16\x03\x03" + packstr(os.urandom(random.choice((32, 40)))))[:-10]))

    async def init_server_data(self, reader, writer, cipher, raddr):
        key = cipher.cipher(cipher.key).key
        sessionid = os.urandom(32)
        addhmac = lambda s: s + hmac.new(key+sessionid, s, hashlib.sha1).digest()[:10]
        writer.write(b"\x16\x03\x01" + packstr(b"\x01\x00" + packstr(b'\x03\x03' + addhmac(int(time.time()).to_bytes(4, 'big') + os.urandom(18)) + b"\x20" + sessionid + b"\x00\x1c\xc0\x2b\xc0\x2f\xcc\xa9\xcc\xa8\xcc\x14\xcc\x13\xc0\x0a\xc0\x14\xc0\x09\xc0\x13\x00\x9c\x00\x35\x00\x2f\x00\x0a\x01\x00" + packstr(b"\xff\x01\x00\x01\x00\x00\x00" + packstr(packstr(b"\x00" + packstr(raddr.encode()))) + b"\x00\x17\x00\x00\x00\x23" + packstr(os.urandom((random.randrange(17)+8)*16)) + b"\x00\x0d\x00\x16\x00\x14\x06\x01\x06\x03\x05\x01\x05\x03\x04\x01\x04\x03\x03\x01\x03\x03\x02\x01\x02\x03\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x12\x00\x00\x75\x50\x00\x00\x00\x0b\x00\x02\x01\x00\x00\x0a\x00\x06\x00\x04\x00\x17\x00\x18"))))
        writer.write(addhmac(b'\x14\x03\x03\x00\x01\x01\x16\x03\x03\x00\x20' + os.urandom(22)))

    def add_cipher(self, cipher):
        self.buf = bytearray()
        def decrypt(s):
            self.buf.extend(s)
            ret = b''
            while len(self.buf) >= 5:
                l = int.from_bytes(self.buf[3:5], 'big')
                if len(self.buf) < l:
                    break
                if self.buf[:3] in (b'\x16\x03\x03', b'\x14\x03\x03'):
                    del self.buf[:5+l]
                    continue
                assert self.buf[:3] == b'\x17\x03\x03'
                data = self.buf[5:5+l]
                ret += data
                del self.buf[:5+l]
            return ret
        def pack(s):
            return b'\x17\x03\x03' + packstr(s)
        def encrypt(s):
            ret = b''
            while len(s) > 2048:
                size = min(random.randrange(4096)+100, len(s))
                ret += pack(s[:size])
                s = s[size:]
            if s:
                ret += pack(s)
            return ret
        cipher.pdecrypt2 = decrypt
        cipher.pencrypt2 = encrypt

class Verify_Simple_Plugin(BasePlugin):
    def add_cipher(self, cipher):
        self.buf = bytearray()
        def decrypt(s):
            self.buf.extend(s)
            ret = b''
            while len(self.buf) >= 2:
                l = int.from_bytes(self.buf[:2], 'big')
                if len(self.buf) < l:
                    break
                data = self.buf[2+self.buf[2]:l-4]
                crc = (-1 - binascii.crc32(self.buf[:l-4])) & 0xffffffff
                assert int.from_bytes(self.buf[l-4:l], 'little') == crc
                ret += data
                del self.buf[:l]
            return ret
        def pack(s):
            rnd_data = os.urandom(os.urandom(1)[0] % 16)
            data = bytes([len(rnd_data)+1]) + rnd_data + s
            data = (len(data)+6).to_bytes(2, 'big') + data
            crc = (-1 - binascii.crc32(data)) & 0xffffffff
            return data + crc.to_bytes(4, 'little')
        def encrypt(s):
            ret = b''
            while len(s) > 8100:
                ret += pack(s[:8100])
                s = s[8100:]
            if s:
                ret += pack(s)
            return ret
        cipher.pdecrypt = decrypt
        cipher.pencrypt = encrypt

class Verify_Deflate_Plugin(BasePlugin):
    def add_cipher(self, cipher):
        self.buf = bytearray()
        def decrypt(s):
            self.buf.extend(s)
            ret = b''
            while len(self.buf) >= 2:
                l = int.from_bytes(self.buf[:2], 'big')
                if len(self.buf) < l:
                    break
                ret += zlib.decompress(b'x\x9c' + self.buf[2:l])
                del self.buf[:l]
            return ret
        def pack(s):
            packed = zlib.compress(s)
            return len(packed).to_bytes(2, 'big') + packed[2:]
        def encrypt(s):
            ret = b''
            while len(s) > 32700:
                ret += pack(s[:32700])
                s = s[32700:]
            if s:
                ret += pack(s)
            return ret
        cipher.pdecrypt = decrypt
        cipher.pencrypt = encrypt

PLUGIN = {cls.name(): cls for name, cls in globals().items() if name.endswith('_Plugin')}

def get_plugin(plugin_name):
    if plugin_name not in PLUGIN:
        return f'existing plugins: {sorted(PLUGIN.keys())}', None
    return None, PLUGIN[plugin_name]()

