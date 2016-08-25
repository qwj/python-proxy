import socket, struct, argparse, urllib.parse, time, re, sys, pickle, asyncio, functools, base64, os

CLIENT_TIMEOUT = 10
CONNECTION_TIMEOUT = 90
AUTH_TIME = 86400 * 30
HTTP_LINE = re.compile('([^ ]+) +(.+?) +([^ ]+)')

def all_stat(stats):
    cmd = sys.stdin.readline()
    print('='*70)
    hstat = {}
    for remote_ip, v in stats.items():
        if remote_ip == 0: continue
        stat = [0]*6
        for host_name, v2 in v.items():
            for h in (stat, hstat.setdefault(host_name, [0]*6)):
                for i in range(6):
                    h[i] += v2[i]
        stat = [(f'{i/1024/1024/1024:.1f}G' if i>=1024*1024*1024 else (f'{i/1024/1024:.1f}M' if i>=1024*1024 else f'{i/1024:.1f}K')) for i in stat[:4]] + stat[4:]
        print(remote_ip, f'\tDIRECT: {stat[4]} ({stat[0]},{stat[2]})  PROXY: {stat[5]} ({stat[1]},{stat[3]})')
    print(' '*3+'-'*64)
    hstat = sorted(list(hstat.items()), key=lambda x: sum(x[1]), reverse=True)[:15]
    hlen = max(map(lambda x: len(x[0]), hstat)) if hstat else 0
    for host_name, stat in hstat:
        stat, conn = (stat[0]+stat[1], stat[2]+stat[3]), stat[4]+stat[5]
        stat = [(f'{i/1024/1024/1024:.1f}G' if i>=1024*1024*1024 else (f'{i/1024/1024:.1f}M' if i>=1024*1024 else f'{i/1024:.1f}K')) for i in stat]
        print(host_name.ljust(hlen+5), f'{stat[0]} / {stat[1]}', f'/ {conn}' if conn else '')
    print('='*70)

async def realtime_stat(stats):
    history = [(stats[:4], time.time())]
    while True:
        await asyncio.sleep(1)
        history.append((stats[:4], time.time()))
        i0, t0, i1, t1 = *history[0], *history[-1]
        stat = [(i1[i]-i0[i])/(t1-t0) for i in range(4)]
        stat = [(f'{i/1024/1024:.1f}M/s' if i>=1024*1024 else f'{i/1024:.1f}K/s') for i in stat]
        sys.stdout.write(f'DIRECT: {stats[4]} ({stat[0]},{stat[2]})   PROXY: {stats[5]} ({stat[1]},{stat[3]})\x1b[0K\r')
        sys.stdout.flush()
        if len(history) >= 10:
            del history[:1]

async def channel(reader, writer, stat_bytes, stat_conn):
    try:
        stat_conn(1)
        while True:
            data = await reader.read(65536)
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

async def http_channel(reader, writer, stat_bytes):
    try:
        while True:
            lines = await reader.readuntil(b'\r\n\r\n')
            headers = lines[:-4].decode().split('\r\n')
            method, path, ver = HTTP_LINE.fullmatch(headers.pop(0)).groups()
            lines = '\r\n'.join(i for i in headers if not i.startswith('Proxy-'))
            headers = dict(i.split(': ', 1) for i in headers if ': ' in i)
            newpath = urllib.parse.urlparse(path)._replace(netloc='', scheme='').geturl()
            data = f'{method} {newpath} {ver}\r\n{lines}\r\n\r\n'.encode()
            data += await reader.readexactly(int(headers.get('Content-Length', '0')))
            stat_bytes(len(data))
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()

async def apply_cipher(reader, writer, cipher, read):
    writer_cipher = cipher[0].new(key=cipher[1])
    writer.write(writer_cipher.nonce)
    writer.write = lambda s, o=writer.write, p=writer_cipher.encrypt: o(p(s))
    reader_cipher = cipher[0].new(key=cipher[1], nonce=await read(8))
    reader.feed_data = lambda s, o=reader.feed_data, p=reader_cipher.decrypt: o(p(s))

async def proxy_handler(reader, writer, types, auth, rserver, rtype, rauth, match, block, verbose, stats, auth_tables, cipher, rcipher, **kwargs):
    try:
        initbuf = b''
        pack2 = lambda s: struct.pack('>H', s)
        unpack2 = lambda s: struct.unpack('>H', s)[0]
        packstr = lambda s: struct.pack('B', len(s)) + s
        read = lambda n: asyncio.wait_for(reader.readexactly(n), timeout=CLIENT_TIMEOUT)
        writer.get_extra_info('socket').setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        remote_ip = writer.get_extra_info('peername')[0]
        if cipher:
            await apply_cipher(reader, writer, cipher, read)
        header = await read(1)
        if 'socks' in types and header == b'\x05':
            methods = await read((await read(1))[0])
            if auth and (b'\x00' not in methods or time.time() - auth_tables.get(remote_ip, 0) > AUTH_TIME):
                writer.write(b'\x05\x02')
                assert (await read(1))[0] == 1
                u = await read((await read(1))[0])
                p = await read((await read(1))[0])
                if u+b':'+p != auth:
                    raise Exception('Unauthorized SOCKS')
                writer.write(b'\x01\x00')
            else:
                writer.write(b'\x05\x00')
            if auth:
                auth_tables[remote_ip] = time.time()
            assert (await read(3)) == b'\x05\x01\x00'
            n = (await read(1))[0]
            if n == 1:
                host_name = socket.inet_ntoa(await read(4))
                port = unpack2(await read(2))
                writer.write(b'\x05\x00\x00\x01' + socket.inet_aton(host_name) + pack2(port))
            elif n == 3:
                host_name = (await read((await read(1))[0])).decode()
                port = unpack2(await read(2))
                writer.write(b'\x05\x00\x00\x03' + packstr(host_name.encode()) + pack2(port))
            else:
                raise AssertionError()
            method, path = 'SOCKS', f'{host_name}:{port}'
        elif 'http' in types and header.isalpha():
            lines = header + (await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), timeout=CLIENT_TIMEOUT))
            headers = lines[:-4].decode().split('\r\n')
            method, path, ver = HTTP_LINE.fullmatch(headers.pop(0)).groups()
            lines = '\r\n'.join(i for i in headers if not i.startswith('Proxy-'))
            headers = dict(i.split(': ', 1) for i in headers if ': ' in i)
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
            else:
                url = urllib.parse.urlparse(path)
                host_name = url.hostname
                port = url.port or 80
                newpath = url._replace(netloc='', scheme='').geturl()
                initbuf = f'{method} {newpath} {ver}\r\n{lines}\r\n\r\n'.encode()
                initbuf += await read(int(headers.get('Content-Length', '0')))
        elif 'psocks' in types and (auth and header == auth[:1] or not auth):
            if auth:
                if (await read(len(auth)-1)) != auth[1:]:
                    raise Exception('Unauthorized PSOCKS')
                header = await read(1)
            if header == b'\xff':
                host_name = socket.inet_ntoa(await read(4))
            else:
                host_name = (await read(unpack2(header + (await read(1))))).decode()
            port = unpack2(await read(2))
            method, path = 'PSOCKS', f'{host_name}:{port}'
        else:
            raise Exception('Unsupported protocol')
        if block and block(host_name):
            raise Exception('BLOCKED ' + host_name)
        host_name_2 = '.'.join(host_name.split('.')[-3 if host_name.endswith('.com.cn') else -2:]) if host_name.split('.')[-1].isalpha() else host_name
        tostat = (stats[0], stats.setdefault(remote_ip, {}).setdefault(host_name_2, [0]*6))
        modstat = lambda i: lambda s: [st.__setitem__(i, st[i] + s) for st in tostat]
        viaproxy = bool(rserver and (not match or match(host_name)))
        if viaproxy:
            if rtype == 'psocks':
                rauth = rauth + pack2(len(host_name.encode())) + host_name.encode() + pack2(port)
            elif rtype == 'socks':
                rauth = (b'\x05\x01\x02\x01' + b''.join(packstr(i) for i in rauth.split(b':', 1)) if rauth else b'\x05\x01\x00') + b'\x05\x01\x00\x03' + packstr(host_name.encode()) + pack2(port)
            elif rtype == 'http':
                rauth = (f'CONNECT {host_name}:{port} HTTP/1.1' + (f'\r\nProxy-Authorization: Basic {base64.b64encode(rauth).decode()}' if rauth else '') + '\r\n\r\n').encode()
            else:
                raise AssertionError()
            initbuf = rauth + initbuf
            verbose(f'{method} {path}')
        else:
            rserver = (host_name, port)
            verbose(f'{method.lower()} {path}')
        try:
            reader_remote, writer_remote = await asyncio.wait_for(asyncio.open_connection(*rserver), timeout=CONNECTION_TIMEOUT)
        except asyncio.TimeoutError:
            raise Exception(f'Connection timeout {rserver}')
        try:
            writer_remote.get_extra_info('socket').setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            readr = lambda n: asyncio.wait_for(reader_remote.readexactly(n), timeout=CLIENT_TIMEOUT)
            if viaproxy and rcipher:
                await apply_cipher(reader_remote, writer_remote, rcipher, readr)
            writer_remote.write(initbuf)
            if viaproxy and rtype == 'socks':
                await asyncio.wait_for(reader_remote.readuntil(b'\x00\x05\x00\x00'), timeout=CLIENT_TIMEOUT)
                await readr(6 if (await readr(1))[0] == 1 else (await readr(1))[0] + 2)
            elif viaproxy and rtype == 'http':
                await asyncio.wait_for(reader_remote.readuntil(b'\r\n\r\n'), timeout=CLIENT_TIMEOUT)
        except Exception:
            writer_remote.close()
            raise Exception('Unknown remote protocol')
        asyncio.ensure_future(channel(reader_remote, writer, modstat(2+viaproxy), modstat(4+viaproxy)))
        if method in ('CONNECT', 'SOCKS', 'PSOCKS'):
            asyncio.ensure_future(channel(reader, writer_remote, modstat(viaproxy), lambda s: None))
        else:
            asyncio.ensure_future(http_channel(reader, writer_remote, modstat(viaproxy)))
    except Exception as ex:
        verbose(f'{str(ex) or "Unsupported protocol"} from {remote_ip}')
        try: writer.close()
        except Exception: pass

def main():
    pattern_compile = lambda s: re.compile('|'.join(f'(?:{i.strip()})' for i in open(s) if i.strip() and not i.startswith('#'))).fullmatch
    def addr_compile(s):
        ip, _, port = s.partition(':')
        return (ip, int(port) if port else 18436)
    def cipher_compile(key): #pip install pycryptodome
        from Crypto.Cipher import ChaCha20
        return (ChaCha20, key.encode().rjust(32, b'\x55'))
    parser = argparse.ArgumentParser(description='Proxy server that can tunnel by http,socks,psocks protocol.')
    parser.add_argument('-p', dest='port', type=int, default=8080, help='listen port server bound to (default: 8080)')
    parser.add_argument('-t', dest='types', type=lambda s: s.split(','), default=['socks','http'], help='proxy server protocols (default: socks,http)')
    parser.add_argument('-a', dest='auth', type=lambda s: s.encode(), help='authentication requirement')
    parser.add_argument('-c', dest='cipher', type=cipher_compile, help='cipher key (default: no cipher)')
    parser.add_argument('-rs', dest='rserver', type=addr_compile, help='remote server address (default: direct)')
    parser.add_argument('-rt', dest='rtype', default='psocks', help='remote server type (default: psocks)')
    parser.add_argument('-ra', dest='rauth', default=b'', type=lambda s: s.encode(), help='remote authorization code')
    parser.add_argument('-rc', dest='rcipher', type=cipher_compile, help='remote cipher key (default: no cipher)')
    parser.add_argument('-m', dest='match', type=pattern_compile, help='match pattern file')
    parser.add_argument('-b', dest='block', type=pattern_compile, help='block pattern file')
    parser.add_argument('-v', dest='v', action='store_true', help='print verbose output')
    args = parser.parse_args()
    args.verbose = (lambda s: sys.stdout.write(s+'\x1b[0K\n') and sys.stdout.flush()) if args.v else (lambda s: None)
    args.stats = {0: [0]*6}
    args.auth_tables = pickle.load(open('.auth_tables', 'rb')) if os.path.exists('.auth_tables') else {}
    loop = asyncio.get_event_loop()
    handler = functools.partial(proxy_handler, **vars(args))
    server = loop.run_until_complete(asyncio.start_server(handler, port=args.port))
    print(f'Serving on port {args.port} by {",".join(args.types)} (' + (f'REMOTE: {args.rserver[0]} by {args.rtype})' if args.rserver else 'DIRECT)'))
    if args.v:
        loop.create_task(realtime_stat(args.stats[0]))
        loop.add_reader(sys.stdin, functools.partial(all_stat, args.stats))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print('exit')
    if args.auth_tables:
        pickle.dump(args.auth_tables, open('.auth_tables', 'wb'), pickle.HIGHEST_PROTOCOL)
    for task in asyncio.Task.all_tasks():
        task.cancel()
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()

if __name__ == '__main__':
    main()

