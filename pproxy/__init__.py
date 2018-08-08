import argparse, time, re, asyncio, functools, urllib.parse
from pproxy import proto

__title__ = 'pproxy'
__version__ = "1.6"
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

async def prepare_ciphers(cipher, reader, writer, bind=None, server_side=True):
    if cipher:
        cipher.pdecrypt = cipher.pdecrypt2 = cipher.pencrypt = cipher.pencrypt2 = DUMMY
        for plugin in cipher.plugins:
            if server_side:
                await plugin.init_server_data(reader, writer, cipher, bind)
            else:
                await plugin.init_client_data(reader, writer, cipher)
            plugin.add_cipher(cipher)
        return cipher(reader, writer, cipher.pdecrypt, cipher.pdecrypt2, cipher.pencrypt, cipher.pencrypt2)
    else:
        return None, None

async def proxy_handler(reader, writer, unix, lbind, protos, rserver, block, cipher, verbose=DUMMY, modstat=lambda r,h:lambda i:DUMMY, **kwargs):
    try:
        if unix:
            remote_ip, server_ip, remote_text = 'local', None, 'unix_local'
        else:
            remote_ip, remote_port = writer.get_extra_info('peername')[0:2]
            server_ip = writer.get_extra_info('sockname')[0]
            remote_text = f'{remote_ip}:{remote_port}'
        local_addr = None if server_ip in ('127.0.0.1', '::1', None) else (server_ip, 0)
        reader_cipher, _ = await prepare_ciphers(cipher, reader, writer, server_side=False)
        lproto, host_name, port, initbuf = await proto.parse(protos, reader=reader, writer=writer, authtable=AuthTable(remote_ip), reader_cipher=reader_cipher, sock=writer.get_extra_info('socket'), **kwargs)
        if block and block(host_name):
            raise Exception('BLOCK ' + host_name)
        roption = next(filter(lambda o: o.alive and (not o.match or o.match(host_name)), rserver), None)
        verbose(f'{lproto.name} {remote_text}' + roption.logtext(host_name, port))
        try:
            reader_remote, writer_remote = await asyncio.wait_for(roption.open_connection(host_name, port, local_addr, lbind), timeout=SOCKET_TIMEOUT)
        except asyncio.TimeoutError:
            raise Exception(f'Connection timeout {roption.bind}')
        try:
            await roption.prepare_connection(reader_remote, writer_remote, host_name, port)
            writer_remote.write(initbuf)
        except Exception:
            writer_remote.close()
            raise Exception('Unknown remote protocol')
        m = modstat(remote_ip, host_name)
        lchannel = lproto.http_channel if initbuf else lproto.channel
        asyncio.ensure_future(lproto.channel(reader_remote, writer, m(2+roption.direct), m(4+roption.direct)))
        asyncio.ensure_future(lchannel(reader, writer_remote, m(roption.direct), DUMMY))
    except Exception as ex:
        if not isinstance(ex, asyncio.TimeoutError) and not str(ex).startswith('Connection closed'):
            verbose(f'{str(ex) or "Unsupported protocol"} from {remote_ip}')
        try: writer.close()
        except Exception: pass

async def check_server_alive(interval, rserver, verbose):
    while True:
        await asyncio.sleep(interval)
        for remote in rserver:
            if remote.direct:
                continue
            try:
                _, writer = await asyncio.wait_for(remote.open_connection(None, None, None, None), timeout=SOCKET_TIMEOUT)
            except Exception as ex:
                if remote.alive:
                    verbose(f'{remote.rproto.name} {remote.bind} -> OFFLINE')
                    remote.alive = False
                continue
            if not remote.alive:
                verbose(f'{remote.rproto.name} {remote.bind} -> ONLINE')
                remote.alive = True
            try:
                writer.close()
            except Exception:
                pass

def pattern_compile(filename):
    with open(filename) as f:
        return re.compile('(:?'+''.join('|'.join(i.strip() for i in f if i.strip() and not i.startswith('#')))+')$').match

class ProxyURI(object):
    def __init__(self, **kw):
        self.__dict__.update(kw)
    def logtext(self, host, port):
        if self.direct:
            return f' -> {host}:{port}'
        else:
            return f' -> {self.rproto.name} {self.bind}' + self.relay.logtext(host, port)
    def open_connection(self, host, port, local_addr, lbind):
        if self.direct:
            local_addr = local_addr if lbind == 'in' else (lbind, 0) if lbind else None
            return asyncio.open_connection(host=host, port=port, local_addr=local_addr)
        elif self.unix:
            return asyncio.open_unix_connection(path=self.bind, ssl=self.sslclient, server_hostname='' if self.sslclient else None)
        else:
            local_addr = local_addr if self.lbind == 'in' else (self.lbind, 0) if self.lbind else None
            return asyncio.open_connection(host=self.host_name, port=self.port, ssl=self.sslclient, local_addr=local_addr)
    async def prepare_connection(self, reader_remote, writer_remote, host, port):
        if not self.direct:
            _, writer_cipher_r = await prepare_ciphers(self.cipher, reader_remote, writer_remote, self.bind)
            whost, wport = (host, port) if self.relay.direct else (self.relay.host_name, self.relay.port)
            await self.rproto.connect(reader_remote=reader_remote, writer_remote=writer_remote, rauth=self.auth, host_name=whost, port=wport, writer_cipher_r=writer_cipher_r, sock=writer_remote.get_extra_info('socket'))
            await self.relay.prepare_connection(reader_remote, writer_remote, host, port)
    def start_server(self, handler):
        if self.unix:
            return asyncio.start_unix_server(handler, path=self.bind, ssl=self.sslserver)
        else:
            return asyncio.start_server(handler, host=self.host_name, port=self.port, ssl=self.sslserver)
    @classmethod
    def compile_relay(cls, uri):
        tail = cls.DIRECT
        for urip in reversed(uri.split('__')):
            tail = cls.compile(urip, tail)
        return tail
    @classmethod
    def compile(cls, uri, relay=None):
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
            host_name, _, port = loc.partition(':')
            port = int(port) if port else 8080
        else:
            host_name = port = None
        return ProxyURI(protos=protos, rproto=protos[0], cipher=cipher, auth=url.fragment.encode(), match=match, bind=loc or urlpath, host_name=host_name, port=port, unix=not loc, lbind=lbind, sslclient=sslclient, sslserver=sslserver, alive=True, direct='direct' in rawprotos, relay=relay)
ProxyURI.DIRECT = ProxyURI(direct=True, relay=None, alive=True, match=None)

async def test_url(url, rserver):
    url = urllib.parse.urlparse(url)
    assert url.scheme in ('http', ), f'Unknown scheme {url.scheme}'
    host_name, _, port = url.netloc.partition(':')
    port = int(port) if port else 80 if url.scheme == 'http' else 443
    initbuf = f'GET {url.path or "/"} HTTP/1.1\r\nHost: {host_name}\r\nUser-Agent: pproxy-{__version__}\r\nConnection: close\r\n\r\n'.encode()
    for roption in rserver:
        if roption.direct:
            continue
        print(f'============ {roption.bind} ============')
        try:
            reader, writer = await asyncio.wait_for(roption.open_connection(host_name, port, None, None), timeout=SOCKET_TIMEOUT)
        except asyncio.TimeoutError:
            raise Exception(f'Connection timeout {rserver}')
        try:
            await roption.prepare_connection(reader, writer, host_name, port)
        except Exception:
            writer.close()
            raise Exception('Unknown remote protocol')
        writer.write(initbuf)
        headers = await reader.read_until(b'\r\n\r\n')
        print(headers.decode()[:-4])
        print(f'--------------------------------')
        body = bytearray()
        while 1:
            s = await reader.read_()
            if not s:
                break
            body.extend(s)
        print(body.decode())
    print(f'============ success ============')

def main():
    parser = argparse.ArgumentParser(description=__description__+'\nSupported protocols: http,socks,shadowsocks,shadowsocksr,redirect', epilog='Online help: <https://github.com/qwj/python-proxy>')
    parser.add_argument('-i', dest='listen', default=[], action='append', type=ProxyURI.compile, help='proxy server setting uri (default: http+socks://:8080/)')
    parser.add_argument('-r', dest='rserver', default=[], action='append', type=ProxyURI.compile_relay, help='remote server setting uri (default: direct)')
    parser.add_argument('-b', dest='block', type=pattern_compile, help='block regex rules')
    parser.add_argument('-a', dest='alived', default=0, type=int, help='interval to check remote alive (default: no check)')
    parser.add_argument('-v', dest='v', action='store_true', help='print verbose output')
    parser.add_argument('--ssl', dest='sslfile', help='certfile[,keyfile] if server listen in ssl mode')
    parser.add_argument('--pac', dest='pac', help='http PAC path')
    parser.add_argument('--get', dest='gets', default=[], action='append', help='http custom {path,file}')
    parser.add_argument('--test', dest='testurl', help='test this url for all remote proxies and exit')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    args = parser.parse_args()
    if args.testurl:
        asyncio.run(test_url(args.testurl, args.rserver))
        return
    if not args.listen:
        args.listen.append(ProxyURI.compile_relay('http+socks://:8080/'))
    if not args.rserver or args.rserver[-1].match:
        args.rserver.append(ProxyURI.DIRECT)
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
            server = loop.run_until_complete(option.start_server(handler))
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

