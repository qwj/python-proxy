import asyncio, socket, urllib.parse, time, re, base64, hmac, struct, hashlib

HTTP_LINE = re.compile('([^ ]+) +(.+?) +(HTTP/[^ ]+)$')
packstr = lambda s, n=1: len(s).to_bytes(n, 'big') + s

@asyncio.coroutine
def socks_address_process(reader, n):
    if n in (1, 17):
        data = yield from reader.read_n(4)
        host_name = socket.inet_ntoa(data)
    elif n in (3, 19):
        data = yield from reader.read_n(1)
        data += yield from reader.read_n(data[0])
        host_name = data[1:].decode()
    elif n in (4, 20):
        data = yield from reader.read_n(16)
        host_name = socket.inet_ntop(socket.AF_INET6, data)
    else:
        raise Exception('Unknown address header {}'.format(n))
    data_port = yield from reader.read_n(2)
    return host_name, int.from_bytes(data_port, 'big'), data+data_port

class BaseProtocol:
    def channel(self, reader, writer, stat_bytes, stat_conn):
        try:
            stat_conn(1)
            while True:
                data = yield from reader.read_()
                if not data:
                    break
                stat_bytes(len(data))
                writer.write(data)
                yield from writer.drain()
        except Exception:
            pass
        finally:
            stat_conn(-1)
            writer.close()
    rchannel = channel

class Shadowsocks(BaseProtocol):
    name = 'ss'
    def correct_header(self, header, auth, **kw):
        return auth and header == auth[:1] or not auth and header and header[0] in (1, 3, 4, 17, 19, 20)
    def patch_ota_reader(self, cipher, reader):
        chunk_id = 0
        @asyncio.coroutine
        def patched_read():
            nonlocal chunk_id
            try:
                data_len = int.from_bytes((yield from reader.readexactly(2)), 'big')
            except Exception:
                return None
            checksum_client = yield from reader.readexactly(10)
            data = yield from reader.readexactly(data_len)
            checksum = hmac.new(cipher.iv+chunk_id.to_bytes(4, 'big'), data, hashlib.sha1).digest()
            assert checksum[:10] == checksum_client
            chunk_id += 1
            return data
        reader.read_ = patched_read
    def patch_ota_writer(self, cipher, writer):
        chunk_id = 0
        write = writer.write
        def patched_write(data):
            nonlocal chunk_id
            if not data: return
            checksum = hmac.new(cipher.iv+chunk_id.to_bytes(4, 'big'), data, hashlib.sha1).digest()
            chunk_id += 1
            return write(len(data).to_bytes(2, 'big') + checksum[:10] + data)
        writer.write = patched_write
    @asyncio.coroutine
    def parse(self, header, reader, auth, authtable, reader_cipher, **kw):
        if auth:
            if (yield from reader.read_n(len(auth)-1)) != auth[1:]:
                raise Exception('Unauthorized SS')
            authtable.set_authed()
            header = yield from reader.read_n(1)
        ota = (header[0] & 0x10 == 0x10)
        host_name, port, data = yield from socks_address_process(reader, header[0])
        assert ota or not reader_cipher or not reader_cipher.ota, 'SS client must support OTA'
        if ota and reader_cipher:
            checksum = hmac.new(reader_cipher.iv+reader_cipher.key, header+data, hashlib.sha1).digest()
            assert checksum[:10] == (yield from reader.read_n(10)), 'Unknown OTA checksum'
            self.patch_ota_reader(reader_cipher, reader)
        return host_name, port, b''
    @asyncio.coroutine
    def connect(self, reader_remote, writer_remote, rauth, host_name, port, initbuf, writer_cipher_r, **kw):
        writer_remote.write(rauth)
        if writer_cipher_r and writer_cipher_r.ota:
            rdata = b'\x13' + packstr(host_name.encode()) + port.to_bytes(2, 'big')
            checksum = hmac.new(writer_cipher_r.iv+writer_cipher_r.key, rdata, hashlib.sha1).digest()
            writer_remote.write(rdata + checksum[:10])
            self.patch_ota_writer(writer_cipher_r, writer_remote)
        else:
            writer_remote.write(b'\x03' + packstr(host_name.encode()) + port.to_bytes(2, 'big'))
        writer_remote.write(initbuf)

class Socks(BaseProtocol):
    name = 'socks'
    def correct_header(self, header, **kw):
        return header == b'\x05'
    @asyncio.coroutine
    def parse(self, reader, writer, auth, authtable, **kw):
        methods = yield from reader.read_n((yield from reader.read_n(1))[0])
        if auth and (b'\x00' not in methods or not authtable.authed()):
            writer.write(b'\x05\x02')
            assert (yield from reader.read_n(1))[0] == 1, 'Unknown SOCKS auth'
            u = yield from reader.read_n((yield from reader.read_n(1))[0])
            p = yield from reader.read_n((yield from reader.read_n(1))[0])
            if u+b':'+p != auth:
                raise Exception('Unauthorized SOCKS')
            writer.write(b'\x01\x00')
        else:
            writer.write(b'\x05\x00')
        if auth:
            authtable.set_authed()
        assert (yield from reader.read_n(3)) == b'\x05\x01\x00', 'Unknown SOCKS protocol'
        header = yield from reader.read_n(1)
        host_name, port, data = yield from socks_address_process(reader, header[0])
        writer.write(b'\x05\x00\x00' + header + data)
        return host_name, port, b''
    @asyncio.coroutine
    def connect(self, reader_remote, writer_remote, rauth, host_name, port, initbuf, **kw):
        writer_remote.write((b'\x05\x01\x02\x01' + b''.join(packstr(i) for i in rauth.split(b':', 1)) if rauth else b'\x05\x01\x00') + b'\x05\x01\x00\x03' + packstr(host_name.encode()) + port.to_bytes(2, 'big'))
        writer_remote.write(initbuf)
        yield from reader_remote.read_until(b'\x00\x05\x00\x00')
        header = (yield from reader_remote.read_n(1))[0]
        yield from reader_remote.read_n(6 if header == 1 else (18 if header == 4 else (yield from reader_remote.read_n(1))[0]+2))

class HTTP(BaseProtocol):
    name = 'http'
    def correct_header(self, header, **kw):
        return header and header.isalpha()
    @asyncio.coroutine
    def parse(self, header, reader, writer, auth, authtable, httpget, **kw):
        lines = header + (yield from reader.read_until(b'\r\n\r\n'))
        headers = lines[:-4].decode().split('\r\n')
        method, path, ver = HTTP_LINE.match(headers.pop(0)).groups()
        lines = '\r\n'.join(i for i in headers if not i.startswith('Proxy-'))
        headers = dict(i.split(': ', 1) for i in headers if ': ' in i)
        url = urllib.parse.urlparse(path)
        if method == 'GET' and not url.hostname:
            for path, text in httpget.items():
                if url.path == path:
                    authtable.set_authed()
                    text = (text % dict(host=headers["Host"])).encode()
                    writer.write('{} 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\nCache-Control: max-age=900\r\nContent-Length: {}\r\n\r\n'.format(ver, len(text)).encode() + text)
                    return None, None, None
            raise Exception('404 {} {}'.format(method, path))
        if auth:
            pauth = headers.get('Proxy-Authorization', None)
            httpauth = 'Basic ' + base64.b64encode(auth).decode()
            if not authtable.authed() and pauth != httpauth:
                writer.write('{} 407 Proxy Authentication Required\r\nConnection: close\r\nProxy-Authenticate: Basic realm="simple"\r\n\r\n'.format(ver).encode())
                raise Exception('Unauthorized HTTP')
            authtable.set_authed()
        if method == 'CONNECT':
            host_name, port = path.split(':', 1)
            port = int(port)
            writer.write('{} 200 OK\r\nConnection: close\r\n\r\n'.format(ver).encode())
            return host_name, port, b''
        else:
            url = urllib.parse.urlparse(path)
            host_name = url.hostname
            port = url.port or 80
            newpath = url._replace(netloc='', scheme='').geturl()
            return host_name, port, '{} {} {}\r\n{}\r\n\r\n'.format(method, newpath, ver, lines).encode()
    @asyncio.coroutine
    def connect(self, reader_remote, writer_remote, rauth, host_name, port, initbuf, **kw):
        writer_remote.write(('CONNECT {}:{} HTTP/1.1'.format(host_name, port) + ('\r\nProxy-Authorization: Basic {}'.format(base64.b64encode(rauth).decode()) if rauth else '') + '\r\n\r\n').encode())
        writer_remote.write(initbuf)
        yield from reader_remote.read_until(b'\r\n\r\n')
    def channel(self, reader, writer, stat_bytes, *args):
        try:
            while True:
                data = yield from reader.read_()
                if not data:
                    break
                if b'\r\n' in data and HTTP_LINE.match(data.split(b'\r\n', 1)[0].decode()):
                    if b'\r\n\r\n' not in data:
                        data += yield from reader.readuntil(b'\r\n\r\n')
                    lines, data = data.split(b'\r\n\r\n', 1)
                    headers = lines[:-4].decode().split('\r\n')
                    method, path, ver = HTTP_LINE.match(headers.pop(0)).groups()
                    lines = '\r\n'.join(i for i in headers if not i.startswith('Proxy-'))
                    headers = dict(i.split(': ', 1) for i in headers if ': ' in i)
                    newpath = urllib.parse.urlparse(path)._replace(netloc='', scheme='').geturl()
                    data = '{} {} {}\r\n{}\r\n\r\n'.format(method, newpath, ver, lines).encode() + data
                stat_bytes(len(data))
                writer.write(data)
                yield from writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

SO_ORIGINAL_DST = 80
class Redirect(BaseProtocol):
    name = 'redir'
    def correct_header(self, header, auth, sock, **kw):
        try:
            buf = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
            assert len(buf) == 16
            remote = (socket.inet_ntoa(buf[4:8]), int.from_bytes(buf[2:4], 'big'))
            assert sock.getsockname() != remote
        except Exception:
            return False
        return auth and header == auth[:1] or not auth
    @asyncio.coroutine
    def parse(self, reader, auth, authtable, sock, **kw):
        if auth:
            if (yield from reader.read_n(len(auth)-1)) != auth[1:]:
                raise Exception('Unauthorized Redir')
            authtable.set_authed()
        buf = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        return socket.inet_ntoa(buf[4:8]), int.from_bytes(buf[2:4], 'big'), b''

@asyncio.coroutine
def parse(protos, reader, **kw):
    proto = next(filter(lambda p: p.correct_header(None, **kw), protos), None)
    if proto is None:
        try:
            header = yield from reader.read_n(1)
        except Exception:
            raise Exception('Connection closed')
        proto = next(filter(lambda p: p.correct_header(header, **kw), protos), None)
    else:
        header = None
    if proto is not None:
        ret = yield from proto.parse(header=header, reader=reader, **kw)
        return (proto,) + ret
    raise Exception('Unsupported protocol {}'.format(header))

MAPPINGS = dict(http=HTTP(), socks=Socks(), ss=Shadowsocks(), redir=Redirect(), ssl='', secure='')

def get_protos(rawprotos):
    protos = []
    for s in rawprotos:
        p = MAPPINGS.get(s)
        if p is None:
            return 'existing protocols: {}'.format(list(MAPPINGS.keys())), None
        if p and p not in protos:
            protos.append(p)
    if not protos:
        return 'no protocol specified', None
    return None, protos

