import socket, argparse, urllib.parse, time, re, base64, hmac

AUTH_TIME = 86400 * 30
HTTP_LINE = re.compile('([^ ]+) +(.+?) +(HTTP/[^ ]+)')
packstr = lambda s, n=1: len(s).to_bytes(n, 'big') + s

async def socks_address_process(reader, n):
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

class base:

    @staticmethod
    async def channel(reader, writer, stat_bytes, stat_conn):
        try:
            stat_conn(1)
            while True:
                data = await reader.read_()
                if not data:
                    break
                stat_bytes(len(data))
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
        finally:
            stat_conn(-1)
            writer.close()

class ss(base):

    @staticmethod
    def correct_header(header, auth, **kw):
        return auth and header == auth[:1] or not auth and header[0] in (1, 3, 4, 17, 19, 20)

    @staticmethod
    async def parse(header, reader, writer, auth, auth_tables, remote_ip, reader_cipher, **kw):
        if auth:
            if (await reader.read_n(len(auth)-1)) != auth[1:]:
                raise Exception('Unauthorized SS')
            auth_tables[remote_ip] = time.time()
            header = await reader.read_n(1)
        ota = (header[0] & 0x10 == 0x10)
        host_name, port, data = await socks_address_process(reader, header[0])
        assert ota or not reader_cipher or not reader_cipher.ota, 'SS client must support OTA'
        if ota and reader_cipher:
            checksum = hmac.new(reader_cipher.iv+reader_cipher.key, header+data, 'sha1').digest()
            assert checksum[:10] == await reader.read_n(10), 'Unknown OTA checksum'
            reader_cipher.patch_ota_reader(reader)
        return host_name, port, b''

    @staticmethod
    async def connect(reader_remote, writer_remote, rauth, host_name, port, initbuf, writer_cipher_r, **kw):
        writer_remote.write(rauth)
        if writer_cipher_r and writer_cipher_r.ota:
            rdata = b'\x13' + packstr(host_name.encode()) + port.to_bytes(2, 'big')
            checksum = hmac.new(writer_cipher_r.iv+writer_cipher_r.key, rdata, 'sha1').digest()
            writer_remote.write(rdata + checksum[:10])
            writer_cipher_r.patch_ota_writer(writer_remote)
        else:
            writer_remote.write(b'\x03' + packstr(host_name.encode()) + port.to_bytes(2, 'big'))
        writer_remote.write(initbuf)

class socks(base):

    @staticmethod
    def correct_header(header, **kw):
        return header == b'\x05'

    @staticmethod
    async def parse(header, reader, writer, auth, auth_tables, remote_ip, **kw):
        methods = await reader.read_n((await reader.read_n(1))[0])
        if auth and (b'\x00' not in methods or time.time() - auth_tables.get(remote_ip, 0) > AUTH_TIME):
            writer.write(b'\x05\x02')
            assert (await reader.read_n(1))[0] == 1, 'Unknown SOCKS auth'
            u = await reader.read_n((await reader.read_n(1))[0])
            p = await reader.read_n((await reader.read_n(1))[0])
            if u+b':'+p != auth:
                raise Exception('Unauthorized SOCKS')
            writer.write(b'\x01\x00')
        else:
            writer.write(b'\x05\x00')
        if auth:
            auth_tables[remote_ip] = time.time()
        assert (await reader.read_n(3)) == b'\x05\x01\x00', 'Unknown SOCKS protocol'
        header = (await reader.read_n(1))
        host_name, port, data = await socks_address_process(reader, header[0])
        writer.write(b'\x05\x00\x00' + header + data)
        return host_name, port, b''

    @staticmethod
    async def connect(reader_remote, writer_remote, rauth, host_name, port, initbuf, **kw):
        writer_remote.write((b'\x05\x01\x02\x01' + b''.join(packstr(i) for i in rauth.split(b':', 1)) if rauth else b'\x05\x01\x00') + b'\x05\x01\x00\x03' + packstr(host_name.encode()) + port.to_bytes(2, 'big'))
        writer_remote.write(initbuf)
        await reader_remote.read_until(b'\x00\x05\x00\x00')
        header = (await reader_remote.read_n(1))[0]
        await reader_remote.read_n(6 if header == 1 else (18 if header == 4 else (await reader_remote.read_n(1))[0]+2))

class http(base):

    @staticmethod
    def correct_header(header, **kw):
        return header.isalpha()

    @staticmethod
    async def parse(header, reader, writer, auth, auth_tables, remote_ip, httpget, **kw):
        lines = header + await reader.read_until(b'\r\n\r\n')
        headers = lines[:-4].decode().split('\r\n')
        method, path, ver = HTTP_LINE.fullmatch(headers.pop(0)).groups()
        lines = '\r\n'.join(i for i in headers if not i.startswith('Proxy-'))
        headers = dict(i.split(': ', 1) for i in headers if ': ' in i)
        url = urllib.parse.urlparse(path)
        if method == 'GET' and not url.hostname:
            for path, text in httpget.items():
                if url.path == path:
                    auth_tables[remote_ip] = time.time()
                    text = (text % dict(host=headers["Host"])).encode()
                    writer.write(f'{ver} 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\nCache-Control: max-age=900\r\nContent-Length: {len(text)}\r\n\r\n'.encode() + text)
                    return None, None, None
            raise Exception(f'404 {method} {path}')
        if auth:
            pauth = headers.get('Proxy-Authorization', None)
            httpauth = 'Basic ' + base64.b64encode(auth).decode()
            if time.time() - auth_tables.get(remote_ip, 0) > AUTH_TIME and pauth != httpauth:
                writer.write(f'{ver} 407 Proxy Authentication Required\r\nConnection: close\r\nProxy-Authenticate: Basic realm="simple"\r\n\r\n'.encode())
                raise Exception('Unauthorized HTTP')
            auth_tables[remote_ip] = time.time()
        if method == 'CONNECT':
            host_name, port = path.split(':', 1)
            port = int(port)
            writer.write(f'{ver} 200 OK\r\nConnection: close\r\n\r\n'.encode())
            return host_name, port, b''
        else:
            url = urllib.parse.urlparse(path)
            host_name = url.hostname
            port = url.port or 80
            newpath = url._replace(netloc='', scheme='').geturl()
            return host_name, port, f'{method} {newpath} {ver}\r\n{lines}\r\n\r\n'.encode()

    @staticmethod
    async def connect(reader_remote, writer_remote, rauth, host_name, port, initbuf, **kw):
        writer_remote.write((f'CONNECT {host_name}:{port} HTTP/1.1' + (f'\r\nProxy-Authorization: Basic {base64.b64encode(rauth).decode()}' if rauth else '') + '\r\n\r\n').encode())
        writer_remote.write(initbuf)
        await reader_remote.read_until(b'\r\n\r\n')

    @staticmethod
    async def channel(reader, writer, stat_bytes, *args):
        try:
            while True:
                data = await reader.read_()
                if not data:
                    break
                if b'\r\n' in data and HTTP_LINE.fullmatch(data.split(b'\r\n', 1)[0].decode()):
                    if b'\r\n\r\n' not in data:
                        data += await reader.readuntil(b'\r\n\r\n')
                    lines, data = data.split(b'\r\n\r\n', 1)
                    headers = lines[:-4].decode().split('\r\n')
                    method, path, ver = HTTP_LINE.fullmatch(headers.pop(0)).groups()
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
            writer.close()

async def parse(protos, header, **kw):
    for proto in protos:
        if proto.correct_header(header, **kw):
            ret = await proto.parse(header, **kw)
            return (proto,) + ret
    raise Exception(f'Unsupported protocol {header}')

MAPPINGS = dict(http=http, socks=socks, ss=ss, ssl=None, secure=None)

def find(s):
    if s not in MAPPINGS:
        raise argparse.ArgumentTypeError(f'existing protocols: {list(MAPPINGS.keys())}')
    return MAPPINGS[s]

