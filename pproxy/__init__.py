import argparse, time, re, asyncio, functools, types, urllib.parse
from pproxy import proto

__title__ = 'pproxy'
__version__ = "1.5.1"
__description__ = "Proxy server that can tunnel among remote servers by regex rules."
__author__ = "Qian Wenjie"
__license__ = "MIT License"

SOCKET_TIMEOUT = 300
PACKET_SIZE = 65536
DUMMY = lambda s: s

asyncio.StreamReader.read_ = lambda self: self.read(PACKET_SIZE)
asyncio.StreamReader.read_n = lambda self, n: asyncio.wait_for(self.readexactly(n), timeout=SOCKET_TIMEOUT)
asyncio.StreamReader.read_until = lambda self, s: asyncio.wait_for(self.readuntil(s), timeout=SOCKET_TIMEOUT)

AUTH_TIME = 86400 * 30
class AuthTable(object):
    _auth = {}
    def __init__(self, remote_ip):
        self.remote_ip = remote_ip
    def authed(self):
        return time.time() - self._auth.get(self.remote_ip, 0) <= AUTH_TIME
    def set_authed(self):
        self._auth[self.remote_ip] = time.time()

async def proxy_handler(reader, writer, unix, lbind, protos, rserver, block, cipher, verbose=DUMMY, modstat=lambda r,h:lambda i:DUMMY, **kwargs):
    try:
        if not unix:
            remote_ip = writer.get_extra_info('peername')[0]
            server_ip = writer.get_extra_info('sockname')[0]
        else:
            remote_ip = server_ip = 'local'
        local_addr = None if server_ip in ('127.0.0.1', '::1', 'local') else (server_ip, 0)
        if cipher:
            reader.plugin_decrypt = reader.plugin_decrypt2 = writer.plugin_encrypt = writer.plugin_encrypt2 = DUMMY
            for plugin in cipher.plugins:
                await plugin.init_client_data(reader, writer, cipher)
                plugin.apply_cipher(reader, writer)
            reader_cipher = cipher(reader, writer)[0]
        else:
            reader_cipher = None
        lproto, host_name, port, initbuf = await proto.parse(protos, reader=reader, writer=writer, authtable=AuthTable(remote_ip), reader_cipher=reader_cipher, sock=writer.get_extra_info('socket'), **kwargs)
        if host_name is None:
            writer.close()
            return
        if block and block(host_name):
            raise Exception('BLOCK ' + host_name)
        roption = next(filter(lambda o: o.alive and (not o.match or o.match(host_name)), rserver), None)
        viaproxy = bool(roption)
        if viaproxy:
            verbose(f'{lproto.name} {host_name}:{port} -> {roption.rproto.name} {roption.bind}')
            wait_connect = roption.connect() if roption.unix else roption.connect(local_addr=local_addr if roption.lbind == 'in' else (roption.lbind, 0) if roption.lbind else None)
        else:
            verbose(f'{lproto.name} {host_name}:{port}')
            wait_connect = asyncio.open_connection(host=host_name, port=port, local_addr=local_addr if lbind == 'in' else (lbind, 0) if lbind else None)
        try:
            reader_remote, writer_remote = await asyncio.wait_for(wait_connect, timeout=SOCKET_TIMEOUT)
        except asyncio.TimeoutError:
            raise Exception(f'Connection timeout {rserver}')
        try:
            if viaproxy:
                if roption.cipher:
                    reader_remote.plugin_decrypt = reader_remote.plugin_decrypt2 = writer_remote.plugin_encrypt = writer_remote.plugin_encrypt2 = DUMMY
                    for plugin in roption.cipher.plugins:
                        await plugin.init_server_data(reader_remote, writer_remote, roption.cipher, roption.bind)
                        plugin.apply_cipher(reader_remote, writer_remote)
                    writer_cipher_r = roption.cipher(reader_remote, writer_remote)[1]
                else:
                    writer_cipher_r = None
                await roption.rproto.connect(reader_remote=reader_remote, writer_remote=writer_remote, rauth=roption.auth, host_name=host_name, port=port, initbuf=initbuf, writer_cipher_r=writer_cipher_r, sock=writer_remote.get_extra_info('socket'))
            else:
                writer_remote.write(initbuf)
        except Exception:
            writer_remote.close()
            raise Exception('Unknown remote protocol')
        m = modstat(remote_ip, host_name)
        asyncio.ensure_future(lproto.rchannel(reader_remote, writer, m(2+viaproxy), m(4+viaproxy)))
        asyncio.ensure_future(lproto.channel(reader, writer_remote, m(viaproxy), DUMMY))
    except Exception as ex:
        if not isinstance(ex, asyncio.TimeoutError) and not str(ex).startswith('Connection closed'):
            verbose(f'{str(ex) or "Unsupported protocol"} from {remote_ip}')
        try: writer.close()
        except Exception: pass

async def check_server_alive(interval, rserver, verbose):
    while True:
        await asyncio.sleep(interval)
        for remote in rserver:
            try:
                reader, writer = await asyncio.wait_for(remote.connect(), timeout=SOCKET_TIMEOUT)
            except Exception as ex:
                if remote.alive:
                    verbose(f'{remote.bind} -> OFFLINE')
                    remote.alive = False
                continue
            if not remote.alive:
                verbose(f'{remote.bind} -> ONLINE')
                remote.alive = True
            try:
                writer.close()
            except Exception:
                pass

def pattern_compile(filename):
    with open(filename) as f:
        return re.compile('(:?'+''.join('|'.join(i.strip() for i in f if i.strip() and not i.startswith('#')))+')$').match

def uri_compile(uri):
    url = urllib.parse.urlparse(uri)
    rawprotos = url.scheme.split('+')
    err_str, protos = proto.get_protos(rawprotos)
    if err_str:
        raise argparse.ArgumentTypeError(err_str)
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
    urlpath, _, plugins = url.path.partition(',')
    urlpath, _, lbind = urlpath.partition('@')
    plugins = plugins.split(',') if plugins else None
    cipher, _, loc = url.netloc.rpartition('@')
    if cipher:
        from pproxy.cipher import get_cipher
        err_str, cipher = get_cipher(cipher)
        if err_str:
            raise argparse.ArgumentTypeError(err_str)
        if plugins:
            from pproxy.plugin import get_plugin
            for name in plugins:
                if not name: continue
                err_str, plugin = get_plugin(name)
                if err_str:
                    raise argparse.ArgumentTypeError(err_str)
                cipher.plugins.append(plugin)
    match = pattern_compile(url.query) if url.query else None
    if loc:
        host, _, port = loc.partition(':')
        port = int(port) if port else 8080
        connect = functools.partial(asyncio.open_connection, host=host, port=port, ssl=sslclient)
        server = functools.partial(asyncio.start_server, host=host, port=port, ssl=sslserver)
    else:
        connect = functools.partial(asyncio.open_unix_connection, path=urlpath, ssl=sslclient, server_hostname='' if sslclient else None)
        server = functools.partial(asyncio.start_unix_server, path=urlpath, ssl=sslserver)
    return types.SimpleNamespace(protos=protos, rproto=protos[0], cipher=cipher, auth=url.fragment.encode(), match=match, server=server, connect=connect, bind=loc or urlpath, unix=not loc, lbind=lbind, sslclient=sslclient, sslserver=sslserver, alive=True)

def main():
    parser = argparse.ArgumentParser(description=__description__+'\nSupported protocols: http,socks,shadowsocks,shadowsocksr,redirect', epilog='Online help: <https://github.com/qwj/python-proxy>')
    parser.add_argument('-i', dest='listen', default=[], action='append', type=uri_compile, help='proxy server setting uri (default: http+socks://:8080/)')
    parser.add_argument('-r', dest='rserver', default=[], action='append', type=uri_compile, help='remote server setting uri (default: direct)')
    parser.add_argument('-b', dest='block', type=pattern_compile, help='block regex rules')
    parser.add_argument('-a', dest='alived', default=0, type=int, help='interval to check remote alive (default: no check)')
    parser.add_argument('-v', dest='v', action='store_true', help='print verbose output')
    parser.add_argument('--ssl', dest='sslfile', help='certfile[,keyfile] if server listen in ssl mode')
    parser.add_argument('--pac', dest='pac', help='http PAC path')
    parser.add_argument('--get', dest='gets', default=[], action='append', help='http custom path/file')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    args = parser.parse_args()
    if not args.listen:
        args.listen.append(uri_compile('http+socks://:8080/'))
    args.httpget = {}
    if args.pac:
        pactext = 'function FindProxyForURL(u,h){' + (f'var b=/^(:?{args.block.__self__.pattern})$/i;if(b.test(h))return "";' if args.block else '')
        for i, option in enumerate(args.rserver):
            pactext += (f'var m{i}=/^(:?{option.match.__self__.pattern})$/i;if(m{i}.test(h))' if option.match else '') + 'return "PROXY %(host)s";'
        args.httpget[args.pac] = pactext+'return "DIRECT";}'
        args.httpget[args.pac+'/all'] = 'function FindProxyForURL(u,h){return "PROXY %(host)s";}'
        args.httpget[args.pac+'/none'] = 'function FindProxyForURL(u,h){return "DIRECT";}'
    for gets in args.gets:
        path, filename = gets.split(',', 1)
        with open(filename, 'rb') as f:
            args.httpget[path] = f.read()
    if args.sslfile:
        sslfile = args.sslfile.split(',')
        for option in args.listen:
            if option.sslclient:
                option.sslclient.load_cert_chain(*sslfile)
                option.sslserver.load_cert_chain(*sslfile)
    elif any(map(lambda o: o.sslclient, args.listen)):
        print('You must specify --ssl to listen in ssl mode')
        return
    loop = asyncio.get_event_loop()
    if args.v:
        from pproxy import verbose
        verbose.setup(loop, args)
    servers = []
    for option in args.listen:
        print('Serving on', option.bind, 'by', ",".join(i.name for i in option.protos) + ('(SSL)' if option.sslclient else ''), '({}{})'.format(option.cipher.name, ' '+','.join(i.name() for i in option.cipher.plugins) if option.cipher and option.cipher.plugins else '') if option.cipher else '')
        handler = functools.partial(proxy_handler, **vars(args), **vars(option))
        try:
            server = loop.run_until_complete(option.server(handler))
            servers.append(server)
        except Exception as ex:
            print('Start server failed.\n\t==>', ex)
    if servers:
        if args.alived > 0 and args.rserver:
            asyncio.ensure_future(check_server_alive(args.alived, args.rserver, args.verbose if args.v else DUMMY))
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            print('exit')
    for task in asyncio.Task.all_tasks():
        task.cancel()
    for server in servers:
        server.close()
    for server in servers:
        loop.run_until_complete(server.wait_closed())
    loop.close()

