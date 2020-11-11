import asyncio, socket, urllib.parse, time, re, base64, hmac, struct, hashlib, io, os

HTTP_LINE = re.compile('([^ ]+) +(.+?) +(HTTP/[^ ]+)$')
packstr = lambda s, n=1: len(s).to_bytes(n, 'big') + s

async def socks_address_stream(reader, n):
    if n in (1, 17):
        data = await reader.read_n(4)
        host_name = socket.inet_ntoa(data)
    elif n in (3, 19):
        data = await reader.read_n(1)
        data += await reader.read_n(data[0])
        host_name = data[1:].decode()
    elif n in (4, 20):
        data = await reader.read_n(16)
        host_name = socket.inet_ntop(socket.AF_INET6, data)
    else:
        raise Exception(f'Unknown address header {n}')
    data_port = await reader.read_n(2)
    return host_name, int.from_bytes(data_port, 'big'), data+data_port

def socks_address(reader, n):
    return socket.inet_ntoa(reader.read(4)) if n == 1 else \
           reader.read(reader.read(1)[0]).decode() if n == 3 else \
           socket.inet_ntop(socket.AF_INET6, reader.read(16)), \
           int.from_bytes(reader.read(2), 'big')

class BaseProtocol:
    def __init__(self, param):
        self.param = param
    @property
    def name(self):
        return self.__class__.__name__.lower()
    def reuse(self):
        return False
    def udp_accept(self, data, **kw):
        raise Exception(f'{self.name} don\'t support UDP server')
    def udp_connect(self, rauth, host_name, port, data, **kw):
        raise Exception(f'{self.name} don\'t support UDP client')
    def udp_unpack(self, data):
        return data
    def udp_pack(self, host_name, port, data):
        return data
    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, **kw):
        raise Exception(f'{self.name} don\'t support client')
    async def channel(self, reader, writer, stat_bytes, stat_conn):
        try:
            stat_conn(1)
            while True:
                data = await reader.read_()
                if not data:
                    break
                if stat_bytes is None:
                    continue
                stat_bytes(len(data))
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
        finally:
            stat_conn(-1)
            writer.close()

class Direct(BaseProtocol):
    pass

class Trojan(BaseProtocol):
    async def guess(self, reader, users, **kw):
        header = await reader.read_w(56)
        if users:
            for user in users:
                if hashlib.sha224(user).hexdigest().encode() == header:
                    return user
        else:
            if hashlib.sha224(b'').hexdigest().encode() == header:
                return True
        reader.rollback(header)
    async def accept(self, reader, user, **kw):
        assert await reader.read_n(2) == b'\x0d\x0a'
        if (await reader.read_n(1))[0] != 1:
            raise Exception('Connection closed')
        host_name, port, _ = await socks_address_stream(reader, (await reader.read_n(1))[0])
        assert await reader.read_n(2) == b'\x0d\x0a'
        return user, host_name, port
    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, **kw):
        toauth = hashlib.sha224(rauth or b'').hexdigest().encode()
        writer_remote.write(toauth + b'\x0d\x0a\x01\x03' + packstr(host_name.encode()) + port.to_bytes(2, 'big') + b'\x0d\x0a')

class SSR(BaseProtocol):
    async def guess(self, reader, users, **kw):
        if users:
            header = await reader.read_w(max(len(i) for i in users))
            reader.rollback(header)
            user = next(filter(lambda x: x == header[:len(x)], users), None)
            if user is None:
                return
            await reader.read_n(len(user))
            return user
        header = await reader.read_w(1)
        reader.rollback(header)
        return header[0] in (1, 3, 4, 17, 19, 20)
    async def accept(self, reader, user, **kw):
        host_name, port, data = await socks_address_stream(reader, (await reader.read_n(1))[0])
        return user, host_name, port
    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, **kw):
        writer_remote.write(rauth + b'\x03' + packstr(host_name.encode()) + port.to_bytes(2, 'big'))

class SS(SSR):
    def patch_ota_reader(self, cipher, reader):
        chunk_id, data_len, _buffer = 0, None, bytearray()
        def decrypt(s):
            nonlocal chunk_id, data_len
            _buffer.extend(s)
            ret = bytearray()
            while 1:
                if data_len is None:
                    if len(_buffer) < 2:
                        break
                    data_len = int.from_bytes(_buffer[:2], 'big')
                    del _buffer[:2]
                else:
                    if len(_buffer) < 10+data_len:
                        break
                    data = _buffer[10:10+data_len]
                    assert _buffer[:10] == hmac.new(cipher.iv+chunk_id.to_bytes(4, 'big'), data, hashlib.sha1).digest()[:10]
                    del _buffer[:10+data_len]
                    data_len = None
                    chunk_id += 1
                    ret.extend(data)
            return bytes(ret)
        reader.decrypts.append(decrypt)
        if reader._buffer:
            reader._buffer = bytearray(decrypt(reader._buffer))
    def patch_ota_writer(self, cipher, writer):
        chunk_id = 0
        def write(data, o=writer.write):
            nonlocal chunk_id
            if not data: return
            checksum = hmac.new(cipher.iv+chunk_id.to_bytes(4, 'big'), data, hashlib.sha1).digest()
            chunk_id += 1
            return o(len(data).to_bytes(2, 'big') + checksum[:10] + data)
        writer.write = write
    async def accept(self, reader, user, reader_cipher, **kw):
        header = await reader.read_n(1)
        ota = (header[0] & 0x10 == 0x10)
        host_name, port, data = await socks_address_stream(reader, header[0])
        assert ota or not reader_cipher or not reader_cipher.ota, 'SS client must support OTA'
        if ota and reader_cipher:
            checksum = hmac.new(reader_cipher.iv+reader_cipher.key, header+data, hashlib.sha1).digest()
            assert checksum[:10] == await reader.read_n(10), 'Unknown OTA checksum'
            self.patch_ota_reader(reader_cipher, reader)
        return user, host_name, port
    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, writer_cipher_r, **kw):
        writer_remote.write(rauth)
        if writer_cipher_r and writer_cipher_r.ota:
            rdata = b'\x13' + packstr(host_name.encode()) + port.to_bytes(2, 'big')
            checksum = hmac.new(writer_cipher_r.iv+writer_cipher_r.key, rdata, hashlib.sha1).digest()
            writer_remote.write(rdata + checksum[:10])
            self.patch_ota_writer(writer_cipher_r, writer_remote)
        else:
            writer_remote.write(b'\x03' + packstr(host_name.encode()) + port.to_bytes(2, 'big'))
    def udp_accept(self, data, users, **kw):
        reader = io.BytesIO(data)
        user = True
        if users:
            user = next(filter(lambda i: data[:len(i)]==i, users), None)
            if user is None:
                return
            reader.read(len(user))
        n = reader.read(1)[0]
        if n not in (1, 3, 4):
            return
        host_name, port = socks_address(reader, n)
        return user, host_name, port, reader.read()
    def udp_unpack(self, data):
        reader = io.BytesIO(data)
        n = reader.read(1)[0]
        host_name, port = socks_address(reader, n)
        return reader.read()
    def udp_pack(self, host_name, port, data):
        try:
            return b'\x01' + socket.inet_aton(host_name) + port.to_bytes(2, 'big') + data
        except Exception:
            pass
        return b'\x03' + packstr(host_name.encode()) + port.to_bytes(2, 'big') + data
    def udp_connect(self, rauth, host_name, port, data, **kw):
        return rauth + b'\x03' + packstr(host_name.encode()) + port.to_bytes(2, 'big') + data

class Socks4(BaseProtocol):
    async def guess(self, reader, **kw):
        header = await reader.read_w(1)
        if header == b'\x04':
            return True
        reader.rollback(header)
    async def accept(self, reader, user, writer, users, authtable, **kw):
        assert await reader.read_n(1) == b'\x01'
        port = int.from_bytes(await reader.read_n(2), 'big')
        ip = await reader.read_n(4)
        userid = (await reader.read_until(b'\x00'))[:-1]
        user = authtable.authed()
        if users:
            if userid in users:
                user = userid
            elif not user:
                raise Exception(f'Unauthorized SOCKS {userid}')
            authtable.set_authed(user)
        writer.write(b'\x00\x5a' + port.to_bytes(2, 'big') + ip)
        return user, socket.inet_ntoa(ip), port
    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, **kw):
        ip = socket.inet_aton((await asyncio.get_event_loop().getaddrinfo(host_name, port, family=socket.AF_INET))[0][4][0])
        writer_remote.write(b'\x04\x01' + port.to_bytes(2, 'big') + ip + rauth + b'\x00')
        assert await reader_remote.read_n(2) == b'\x00\x5a'
        await reader_remote.read_n(6)

class Socks5(BaseProtocol):
    async def guess(self, reader, **kw):
        header = await reader.read_w(1)
        if header == b'\x05':
            return True
        reader.rollback(header)
    async def accept(self, reader, user, writer, users, authtable, **kw):
        methods = await reader.read_n((await reader.read_n(1))[0])
        user = authtable.authed()
        if users and (not user or b'\x00' not in methods):
            if b'\x02' not in methods:
                raise Exception(f'Unauthorized SOCKS')
            writer.write(b'\x05\x02')
            assert (await reader.read_n(1))[0] == 1, 'Unknown SOCKS auth'
            u = await reader.read_n((await reader.read_n(1))[0])
            p = await reader.read_n((await reader.read_n(1))[0])
            user = u+b':'+p
            if user not in users:
                raise Exception(f'Unauthorized SOCKS {u}:{p}')
            writer.write(b'\x01\x00')
        elif users and not user:
            raise Exception(f'Unauthorized SOCKS')
        else:
            writer.write(b'\x05\x00')
        if users:
            authtable.set_authed(user)
        assert await reader.read_n(3) == b'\x05\x01\x00', 'Unknown SOCKS protocol'
        header = await reader.read_n(1)
        host_name, port, data = await socks_address_stream(reader, header[0])
        writer.write(b'\x05\x00\x00' + header + data)
        return user, host_name, port
    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, **kw):
        if rauth:
            writer_remote.write(b'\x05\x01\x02')
            assert await reader_remote.read_n(2) == b'\x05\x02'
            writer_remote.write(b'\x01' + b''.join(packstr(i) for i in rauth.split(b':', 1)))
            assert await reader_remote.read_n(2) == b'\x01\x00', 'Unknown SOCKS auth'
        else:
            writer_remote.write(b'\x05\x01\x00')
            assert await reader_remote.read_n(2) == b'\x05\x00'
        writer_remote.write(b'\x05\x01\x00\x03' + packstr(host_name.encode()) + port.to_bytes(2, 'big'))
        assert await reader_remote.read_n(3) == b'\x05\x00\x00'
        header = (await reader_remote.read_n(1))[0]
        await reader_remote.read_n(6 if header == 1 else (18 if header == 4 else (await reader_remote.read_n(1))[0]+2))
    def udp_accept(self, data, **kw):
        reader = io.BytesIO(data)
        if reader.read(3) != b'\x00\x00\x00':
            return
        n = reader.read(1)[0]
        if n not in (1, 3, 4):
            return
        host_name, port = socks_address(reader, n)
        return True, host_name, port, reader.read()
    def udp_connect(self, rauth, host_name, port, data, **kw):
        return b'\x00\x00\x00\x03' + packstr(host_name.encode()) + port.to_bytes(2, 'big') + data

class HTTP(BaseProtocol):
    async def guess(self, reader, **kw):
        header = await reader.read_w(4)
        reader.rollback(header)
        return header in (b'GET ', b'HEAD', b'POST', b'PUT ', b'DELE', b'CONN', b'OPTI', b'TRAC', b'PATC')
    async def accept(self, reader, user, writer, users, authtable, httpget=None, **kw):
        lines = await reader.read_until(b'\r\n\r\n')
        headers = lines[:-4].decode().split('\r\n')
        method, path, ver = HTTP_LINE.match(headers.pop(0)).groups()
        lines = '\r\n'.join(i for i in headers if not i.startswith('Proxy-'))
        headers = dict(i.split(': ', 1) for i in headers if ': ' in i)
        url = urllib.parse.urlparse(path)
        if method == 'GET' and not url.hostname and httpget:
            for path, text in httpget.items():
                if path == url.path:
                    user = next(filter(lambda x: x.decode()==url.query, users), None) if users else True
                    if user:
                        if users:
                            authtable.set_authed(user)
                        if type(text) is str:
                            text = (text % dict(host=headers["Host"])).encode()
                        writer.write(f'{ver} 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\nCache-Control: max-age=900\r\nContent-Length: {len(text)}\r\n\r\n'.encode() + text)
                        await writer.drain()
                        raise Exception('Connection closed')
            raise Exception(f'404 {method} {url.path}')
        if users:
            pauth = headers.get('Proxy-Authorization', None)
            user = authtable.authed()
            if not user:
                user = next(filter(lambda i: ('Basic '+base64.b64encode(i).decode()) == pauth, users), None)
                if user is None:
                    writer.write(f'{ver} 407 Proxy Authentication Required\r\nConnection: close\r\nProxy-Authenticate: Basic realm="simple"\r\n\r\n'.encode())
                    raise Exception('Unauthorized HTTP')
            authtable.set_authed(user)
        if method == 'CONNECT':
            host_name, port = path.rsplit(':', 1)
            port = int(port)
            return user, host_name, port, f'{ver} 200 OK\r\nConnection: close\r\n\r\n'.encode()
        else:
            url = urllib.parse.urlparse(path)
            if ':' in url.netloc:
                host_name, port = url.netloc.rsplit(':', 1)
                port = int(port)
            else:
                host_name, port = url.netloc, 80
            newpath = url._replace(netloc='', scheme='').geturl()
            return user, host_name, port, b'', f'{method} {newpath} {ver}\r\n{lines}\r\n\r\n'.encode()
    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, myhost, **kw):
        writer_remote.write(f'CONNECT {host_name}:{port} HTTP/1.1\r\nHost: {myhost}'.encode() + (b'\r\nProxy-Authorization: Basic '+base64.b64encode(rauth) if rauth else b'') + b'\r\n\r\n')
        await reader_remote.read_until(b'\r\n\r\n')
    async def http_channel(self, reader, writer, stat_bytes, stat_conn):
        try:
            stat_conn(1)
            while True:
                data = await reader.read_()
                if not data:
                    break
                if b'\r\n' in data and HTTP_LINE.match(data.split(b'\r\n', 1)[0].decode()):
                    if b'\r\n\r\n' not in data:
                        data += await reader.readuntil(b'\r\n\r\n')
                    lines, data = data.split(b'\r\n\r\n', 1)
                    headers = lines.decode().split('\r\n')
                    method, path, ver = HTTP_LINE.match(headers.pop(0)).groups()
                    lines = '\r\n'.join(i for i in headers if not i.startswith('Proxy-'))
                    headers = dict(i.split(': ', 1) for i in headers if ': ' in i)
                    newpath = urllib.parse.urlparse(path)._replace(netloc='', scheme='').geturl()
                    data = f'{method} {newpath} {ver}\r\n{lines}\r\n\r\n'.encode() + data
                stat_bytes(len(data))
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
        finally:
            stat_conn(-1)
            writer.close()

class HTTPOnly(HTTP):
    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, myhost, **kw):
        buffer = bytearray()
        HOST_NAME = re.compile('\r\nHost: ([^\r\n]+)\r\n', re.I)
        def write(data, o=writer_remote.write):
            if not data: return
            buffer.extend(data)
            pos = buffer.find(b'\r\n\r\n')
            if pos != -1:
                text = buffer[:pos].decode()
                header = HTTP_LINE.match(text.split('\r\n', 1)[0])
                host = HOST_NAME.search(text)
                if not header or not host:
                    writer_remote.close()
                    raise Exception('Unknown HTTP header for protocol HTTPOnly')
                method, path, ver = header.groups()
                data = f'{method} http://{host.group(1)}{path} {ver}\r\nHost: {host.group(1)}'.encode() + (b'\r\nProxy-Authorization: Basic '+base64.b64encode(rauth) if rauth else b'') + b'\r\n\r\n' + buffer[pos+4:]
                buffer.clear()
                return o(data)
        writer_remote.write = write

class SSH(BaseProtocol):
    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, myhost, **kw):
        pass

class Transparent(BaseProtocol):
    async def guess(self, reader, sock, **kw):
        remote = self.query_remote(sock)
        return remote is not None and sock.getsockname() != remote
    async def accept(self, reader, user, sock, **kw):
        remote = self.query_remote(sock)
        return user, remote[0], remote[1]
    def udp_accept(self, data, sock, **kw):
        remote = self.query_remote(sock)
        return True, remote[0], remote[1], data

SO_ORIGINAL_DST = 80
SOL_IPV6 = 41
class Redir(Transparent):
    def query_remote(self, sock):
        try:
            #if sock.family == socket.AF_INET:
            if "." in sock.getsockname()[0]:
                buf = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
                assert len(buf) == 16
                return socket.inet_ntoa(buf[4:8]), int.from_bytes(buf[2:4], 'big')
            else:
                buf = sock.getsockopt(SOL_IPV6, SO_ORIGINAL_DST, 28)
                assert len(buf) == 28
                return socket.inet_ntop(socket.AF_INET6, buf[8:24]), int.from_bytes(buf[2:4], 'big')
        except Exception:
            pass

class Pf(Transparent):
    def query_remote(self, sock):
        try:
            import fcntl
            src = sock.getpeername()
            dst = sock.getsockname()
            src_ip = socket.inet_pton(sock.family, src[0])
            dst_ip = socket.inet_pton(sock.family, dst[0])
            pnl = bytearray(struct.pack('!16s16s32xHxxHxx8xBBxB', src_ip, dst_ip, src[1], dst[1], sock.family, socket.IPPROTO_TCP, 2))
            if not hasattr(self, 'pf'):
                self.pf = open('/dev/pf', 'a+b')
            fcntl.ioctl(self.pf.fileno(), 0xc0544417, pnl)
            return socket.inet_ntop(sock.family, pnl[48:48+len(src_ip)]), int.from_bytes(pnl[76:78], 'big')
        except Exception:
            pass

class Tunnel(Transparent):
    def query_remote(self, sock):
        if not self.param:
            return 'tunnel', 0
        host, _, port = self.param.partition(':')
        dst = sock.getsockname()
        host = host or dst[0]
        port = int(port) if port else dst[1]
        return host, port
    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, **kw):
        pass
    def udp_connect(self, rauth, host_name, port, data, **kw):
        return data

class WS(BaseProtocol):
    async def guess(self, reader, **kw):
        header = await reader.read_w(4)
        reader.rollback(header)
        return reader == b'GET '
    def patch_ws_stream(self, reader, writer, masked=False):
        data_len, mask_key, _buffer = None, None, bytearray()
        def feed_data(s, o=reader.feed_data):
            nonlocal data_len, mask_key
            _buffer.extend(s)
            while 1:
                if data_len is None:
                    if len(_buffer) < 2:
                        break
                    required = 2 + (4 if _buffer[1]&128 else 0)
                    p = _buffer[1] & 127
                    required += 2 if p == 126 else 4 if p == 127 else 0
                    if len(_buffer) < required:
                        break
                    data_len = int.from_bytes(_buffer[2:4], 'big') if p == 126 else int.from_bytes(_buffer[2:6], 'big') if p == 127 else p
                    mask_key = _buffer[required-4:required] if _buffer[1]&128 else None
                    del _buffer[:required]
                else:
                    if len(_buffer) < data_len:
                        break
                    data = _buffer[:data_len]
                    if mask_key:
                        data = bytes(data[i]^mask_key[i%4] for i in range(data_len))
                    del _buffer[:data_len]
                    data_len = None
                    o(data)
        reader.feed_data = feed_data
        if reader._buffer:
            reader._buffer, buf = bytearray(), reader._buffer
            feed_data(buf)
        def write(data, o=writer.write):
            if not data: return
            data_len = len(data)
            if masked:
                mask_key = os.urandom(4)
                data = bytes(data[i]^mask_key[i%4] for i in range(data_len))
                return o(b'\x02' + (bytes([data_len|0x80]) if data_len < 126 else b'\xfe'+data_len.to_bytes(2, 'big') if data_len < 65536 else b'\xff'+data_len.to_bytes(4, 'big')) + mask_key + data)
            else:
                return o(b'\x02' + (bytes([data_len]) if data_len < 126 else b'\x7e'+data_len.to_bytes(2, 'big') if data_len < 65536 else b'\x7f'+data_len.to_bytes(4, 'big')) + data)
        writer.write = write
    async def accept(self, reader, user, writer, users, authtable, sock, **kw):
        lines = await reader.read_until(b'\r\n\r\n')
        headers = lines[:-4].decode().split('\r\n')
        method, path, ver = HTTP_LINE.match(headers.pop(0)).groups()
        lines = '\r\n'.join(i for i in headers if not i.startswith('Proxy-'))
        headers = dict(i.split(': ', 1) for i in headers if ': ' in i)
        url = urllib.parse.urlparse(path)
        if users:
            pauth = headers.get('Proxy-Authorization', None)
            user = authtable.authed()
            if not user:
                user = next(filter(lambda i: ('Basic '+base64.b64encode(i).decode()) == pauth, users), None)
                if user is None:
                    writer.write(f'{ver} 407 Proxy Authentication Required\r\nConnection: close\r\nProxy-Authenticate: Basic realm="simple"\r\n\r\n'.encode())
                    raise Exception('Unauthorized WebSocket')
            authtable.set_authed(user)
        if method != 'GET':
            raise Exception(f'Unsupported method {method}')
        if headers.get('Sec-WebSocket-Key', None) is None:
            raise Exception(f'Unsupported headers {headers}')
        seckey = base64.b64decode(headers.get('Sec-WebSocket-Key'))
        rseckey = base64.b64encode(hashlib.sha1(seckey+b'amtf').digest()[:16]).decode()
        writer.write(f'{ver} 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {rseckey}\r\nSec-WebSocket-Protocol: chat\r\n\r\n'.encode())
        self.patch_ws_stream(reader, writer, False)
        if not self.param:
            return 'tunnel', 0
        host, _, port = self.param.partition(':')
        dst = sock.getsockname()
        host = host or dst[0]
        port = int(port) if port else dst[1]
        return user, host, port
    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, myhost, **kw):
        seckey = base64.b64encode(os.urandom(16)).decode()
        writer_remote.write(f'GET / HTTP/1.1\r\nHost: {myhost}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {seckey}\r\nSec-WebSocket-Protocol: chat\r\nSec-WebSocket-Version: 13'.encode() + (b'\r\nProxy-Authorization: Basic '+base64.b64encode(rauth) if rauth else b'') + b'\r\n\r\n')
        await reader_remote.read_until(b'\r\n\r\n')
        self.patch_ws_stream(reader_remote, writer_remote, True)

class Echo(Transparent):
    def query_remote(self, sock):
        return 'echo', 0

class Pack(BaseProtocol):
    def reuse(self):
        return True
    def get_handler(self, reader, writer, verbose, tcp_handler=None, udp_handler=None):
        class Handler:
            def __init__(self):
                self.sessions = {}
                self.udpmap = {}
                self.closed = False
                self.ready = False
                asyncio.ensure_future(self.reader_handler())
            def __bool__(self):
                return not self.closed
            async def reader_handler(self):
                try:
                    while True:
                        try:
                            header = (await reader.readexactly(1))[0]
                        except Exception:
                            raise Exception('Connection closed')
                        sid = await reader.read_n(8)
                        if header in (0x01, 0x03, 0x04, 0x11, 0x13, 0x14):
                            host_name, port, _ = await socks_address_stream(reader, header)
                            if (header & 0x10 == 0) and tcp_handler:
                                remote_reader, remote_writer = self.get_streams(sid)
                                asyncio.ensure_future(tcp_handler(remote_reader, remote_writer, host_name, port))
                            elif (header & 0x10 != 0) and udp_handler:
                                self.get_datagram(sid, host_name, port)
                        elif header in (0x20, 0x30):
                            datalen = int.from_bytes(await reader.read_n(2), 'big')
                            data = await reader.read_n(datalen)
                            if header == 0x20 and sid in self.sessions:
                                self.sessions[sid].feed_data(data)
                            elif header == 0x30 and sid in self.udpmap and udp_handler:
                                host_name, port, sendto = self.udpmap[sid]
                                asyncio.ensure_future(udp_handler(sendto, data, host_name, port, sid))
                        elif header == 0x40:
                            if sid in self.sessions:
                                self.sessions.pop(sid).feed_eof()
                        else:
                            raise Exception(f'Unknown header {header}')
                except Exception as ex:
                    if not isinstance(ex, asyncio.TimeoutError) and not str(ex).startswith('Connection closed'):
                        verbose(f'{str(ex) or "Unsupported protocol"}')
                finally:
                    for sid, session in self.sessions.items():
                        session.feed_eof()
                    try: writer.close()
                    except Exception: pass
                    self.closed = True
            def get_streams(self, sid):
                self.sessions[sid] = asyncio.StreamReader()
                class Writer():
                    def write(self, data):
                        while len(data) >= 32*1024:
                            writer.write(b'\x20'+sid+(32*1024).to_bytes(2,'big')+data[:32*1024])
                            data = data[32*1024:]
                        if data:
                            writer.write(b'\x20'+sid+len(data).to_bytes(2,'big')+data)
                    def drain(self):
                        return writer.drain()
                    def close(self):
                        if not writer.transport.is_closing():
                            writer.write(b'\x40'+sid)
                return self.sessions[sid], Writer()
            def connect(self, host_name, port):
                self.ready = True
                sid = os.urandom(8)
                writer.write(b'\x03' + sid + packstr(host_name.encode()) + port.to_bytes(2, 'big'))
                return self.get_streams(sid)
            def get_datagram(self, sid, host_name, port):
                def sendto(data):
                    if data:
                        writer.write(b'\x30'+sid+len(data).to_bytes(2,'big')+data)
                self.udpmap[sid] = (host_name, port, sendto)
                return self.udpmap[sid]
        writer.get_extra_info('socket').setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        return Handler()

async def accept(protos, reader, **kw):
    for proto in protos:
        try:
            user = await proto.guess(reader, **kw)
        except Exception:
            raise Exception('Connection closed')
        if user:
            ret = await proto.accept(reader, user, **kw)
            while len(ret) < 5:
                ret += (b'',)
            return (proto,) + ret
    raise Exception(f'Unsupported protocol')

def udp_accept(protos, data, **kw):
    for proto in protos:
        ret = proto.udp_accept(data, **kw)
        if ret:
            return (proto,) + ret
    raise Exception(f'Unsupported protocol {data[:10]}')

MAPPINGS = dict(direct=Direct, http=HTTP, httponly=HTTPOnly, ssh=SSH, socks5=Socks5, socks4=Socks4, socks=Socks5, ss=SS, ssr=SSR, redir=Redir, pf=Pf, tunnel=Tunnel, echo=Echo, pack=Pack, ws=WS, trojan=Trojan, ssl='', secure='')
MAPPINGS['in'] = ''

def get_protos(rawprotos):
    protos = []
    for s in rawprotos:
        s, _, param = s.partition('{')
        param = param[:-1] if param else None
        p = MAPPINGS.get(s)
        if p is None:
            return f'existing protocols: {list(MAPPINGS.keys())}', None
        if p and p not in protos:
            protos.append(p(param))
    if not protos:
        return 'no protocol specified', None
    return None, protos

def sslwrap(reader, writer, sslcontext, server_side=False, server_hostname=None, verbose=None):
    if sslcontext is None:
        return reader, writer
    ssl_reader = asyncio.StreamReader()
    class Protocol(asyncio.Protocol):
        def data_received(self, data):
            ssl_reader.feed_data(data)
        def eof_received(self):
            ssl_reader.feed_eof()
        def connection_lost(self, exc):
            ssl_reader.feed_eof()
    ssl = asyncio.sslproto.SSLProtocol(asyncio.get_event_loop(), Protocol(), sslcontext, None, server_side, server_hostname, False)
    class Transport(asyncio.Transport):
        _paused = False
        def __init__(self, extra={}):
            self._extra = extra
            self.closed = False
        def write(self, data):
            if data and not self.closed:
                writer.write(data)
        def close(self):
            self.closed = True
            writer.close()
        def _force_close(self, exc):
            if not self.closed:
                (verbose or print)(f'{exc} from {writer.get_extra_info("peername")[0]}')
            self.close()
        def abort(self):
            self.close()
    ssl.connection_made(Transport())
    async def channel():
        try:
            while True:
                data = await reader.read_()
                if not data:
                    break
                ssl.data_received(data)
        except Exception:
            pass
        finally:
            ssl.eof_received()
    asyncio.ensure_future(channel())
    class Writer():
        def get_extra_info(self, key):
            return writer.get_extra_info(key)
        def write(self, data):
            ssl._app_transport.write(data)
        def drain(self):
            return writer.drain()
        def close(self):
            ssl._app_transport.close()
    return ssl_reader, Writer()
