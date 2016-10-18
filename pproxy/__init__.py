import argparse, time, re, pickle, asyncio, functools, types, os, urllib.parse
from pproxy import proto

__title__ = 'pproxy'
__version__ = "0.9.6"
__description__ = "Proxy server that can tunnel among remote servers by regex rules."
__author__ = "Qian Wenjie"
__license__ = "MIT License"

SOCKET_TIMEOUT = 300
PACKET_SIZE = 65536
DUMMY = lambda s: None

asyncio.StreamReader.read_ = lambda self: self.read(PACKET_SIZE)
asyncio.StreamReader.read_n = lambda self, n: asyncio.wait_for(self.readexactly(n), timeout=SOCKET_TIMEOUT)
asyncio.StreamReader.read_until = lambda self, s: asyncio.wait_for(self.readuntil(s), timeout=SOCKET_TIMEOUT)

async def proxy_handler(reader, writer, protos, auth, rserver, block, auth_tables, cipher, httpget, unix_path, verbose=DUMMY, modstat=lambda r,h:lambda i:DUMMY, **kwargs):
    try:
        remote_ip = writer.get_extra_info('peername')[0] if not unix_path else None
        reader_cipher = cipher(reader, writer)[0] if cipher else None
        header = await reader.read_n(1)
        lproto, host_name, port, initbuf = await proto.parse(protos, reader=reader, writer=writer, header=header, auth=auth, auth_tables=auth_tables, remote_ip=remote_ip, httpget=httpget, reader_cipher=reader_cipher)
        if host_name is None:
            writer.close()
            return
        if block and block(host_name):
            raise Exception('BLOCK ' + host_name)
        roption = None
        for option in rserver:
            if not option.match or option.match(host_name):
                roption = option
                break
        viaproxy = bool(roption)
        if viaproxy:
            verbose(f'{lproto.__name__} {host_name}:{port} -> {roption.protos[0].__name__} {roption.bind}')
            connect = roption.connect
        else:
            verbose(f'{lproto.__name__} {host_name}:{port}')
            connect = functools.partial(asyncio.open_connection, host=host_name, port=port)
        try:
            reader_remote, writer_remote = await asyncio.wait_for(connect(), timeout=SOCKET_TIMEOUT)
        except asyncio.TimeoutError:
            raise Exception(f'Connection timeout {rserver}')
        try:
            if viaproxy:
                writer_cipher_r = roption.cipher(reader_remote, writer_remote)[1] if roption.cipher else None
                await roption.protos[0].connect(reader_remote=reader_remote, writer_remote=writer_remote, rauth=roption.auth, host_name=host_name, port=port, initbuf=initbuf, writer_cipher_r=writer_cipher_r)
            else:
                writer_remote.write(initbuf)
        except Exception:
            writer_remote.close()
            raise Exception('Unknown remote protocol')
        m = modstat(remote_ip, host_name)
        asyncio.ensure_future(proto.base.channel(reader_remote, writer, m(2+viaproxy), m(4+viaproxy)))
        asyncio.ensure_future(lproto.channel(reader, writer_remote, m(viaproxy), DUMMY))
    except Exception as ex:
        if not isinstance(ex, asyncio.TimeoutError):
            verbose(f'{str(ex) or "Unsupported protocol"} from {remote_ip}')
        try: writer.close()
        except Exception: pass

def pattern_compile(filename):
    with open(filename) as f:
        return re.compile('|'.join(i.strip() for i in f if i.strip() and not i.startswith('#'))).fullmatch

def uri_compile(uri):
    url = urllib.parse.urlparse(uri)
    rawprotos = url.scheme.split('+')
    protos = list(set(filter(None, (proto.find(i) for i in rawprotos))))
    if 'ssl' in rawprotos or 'secure' in rawprotos:
        import ssl
        sslserver = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        sslclient = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        if 'ssl' in rawprotos:
            sslclient.check_hostname = False
            sslclient.verify_mode = ssl.CERT_NONE
    else:
        sslserver = None
        sslclient = None
    cipher, _, loc = url.netloc.rpartition('@')
    if cipher:
        from pproxy import ciphers
        cipher = ciphers.get_cipher(cipher)
    match = pattern_compile(url.query) if url.query else None
    if loc:
        host, _, port = loc.partition(':')
        port = int(port) if port else 8080
        connect = functools.partial(asyncio.open_connection, host=host, port=port, ssl=sslclient)
        server = functools.partial(asyncio.start_server, host=host, port=port, ssl=sslserver)
    else:
        connect = functools.partial(asyncio.open_unix_connection, path=url.path, ssl=sslclient, server_hostname='' if sslclient else None)
        server = functools.partial(asyncio.start_unix_server, path=url.path, ssl=sslserver)
    return types.SimpleNamespace(sslclient=sslclient, protos=protos, cipher=cipher, auth=url.fragment.encode(), match=match, server=server, connect=connect, bind=loc or url.path, unix_path=not loc, sslserver=sslserver)

def main():
    parser = argparse.ArgumentParser(description=__description__+'\nSupported protocols: http,socks,shadowsocks', epilog='Online help: <https://github.com/qwj/python-proxy>')
    parser.add_argument('-i', dest='listen', default=[], action='append', type=uri_compile, help='proxy server setting uri (default: http+socks://:8080/)')
    parser.add_argument('-r', dest='rserver', default=[], action='append', type=uri_compile, help='remote server setting uri (default: direct)')
    parser.add_argument('-b', dest='block', type=pattern_compile, help='block regex rules')
    parser.add_argument('-v', dest='v', action='store_true', help='print verbose output')
    parser.add_argument('--ssl', dest='sslfile', help='certfile[,keyfile] if server listen in ssl mode')
    parser.add_argument('--pac', dest='pac', help='http PAC path')
    parser.add_argument('--get', dest='gets', default=[], action='append', help='http custom path/file')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    args = parser.parse_args()
    if not args.listen:
        args.listen.append(uri_compile('http+socks://:8080/'))
    if os.path.exists('.auth_tables'):
        with open('.auth_tables', 'rb') as f:
            args.auth_tables = pickle.load(f)
    else:
        args.auth_tables = {}
    args.httpget = {}
    if args.pac:
        pactext = 'function FindProxyForURL(u,h){' + (f'var b=/^(:?{args.block.__self__.pattern})$/i;if(b.test(h))return "";' if args.block else '')
        for i, option in enumerate(args.rserver):
            pactext += (f'var m{i}=/^(:?{option.match.__self__.pattern})$/i;if(m{i}.test(h))' if option.match else '') + f'return "PROXY %(host)s";'
        args.httpget[args.pac] = pactext+'return "DIRECT";}'
        args.httpget[args.pac+'/all'] = 'function FindProxyForURL(u,h){return "PROXY %(host)s";}'
        args.httpget[args.pac+'/none'] = 'function FindProxyForURL(u,h){return "DIRECT";}'
    for gets in args.gets:
        path, filename = gets.split(',', 1)
        with open(filename, 'r') as f:
            args.httpget[path] = f.read()
    if args.sslfile:
        sslfile = args.sslfile.split(',')
        for option in args.listen:
            if option.sslclient:
                option.sslclient.load_cert_chain(*sslfile)
                option.sslserver.load_cert_chain(*sslfile)
    elif any(map(lambda o: o.sslclient, args.listen)):
        print(f'You must specify --ssl to listen in ssl mode')
        return
    loop = asyncio.get_event_loop()
    if args.v:
        from pproxy import verbose
        verbose.setup(loop, args)
    servers = []
    for option in args.listen:
        print(f'Serving on {option.bind} by {",".join(i.__name__ for i in option.protos)}', '(SSL)' if option.sslclient else '')
        handler = functools.partial(proxy_handler, **vars(args), **vars(option))
        server = loop.run_until_complete(option.server(handler))
        servers.append(server)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print('exit')
    if args.auth_tables:
        with open('.auth_tables', 'wb') as f:
            pickle.dump(args.auth_tables, f, pickle.HIGHEST_PROTOCOL)
    for task in asyncio.Task.all_tasks():
        task.cancel()
    for server in servers:
        server.close()
    for server in servers:
        loop.run_until_complete(server.wait_closed())
    loop.close()

