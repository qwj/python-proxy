import argparse, time, re, asyncio, functools, types, urllib.parse
from pproxy import proto

__title__ = 'pproxy'
__version__ = "1.2.1"
__description__ = "Proxy server that can tunnel among remote servers by regex rules."
__author__ = "Qian Wenjie"
__license__ = "MIT License"

SOCKET_TIMEOUT = 300
PACKET_SIZE = 65536
DUMMY = lambda s: None

asyncio.StreamReader.read_ = lambda self: self.read(PACKET_SIZE)
asyncio.StreamReader.read_n = lambda self, n: asyncio.wait_for(self.readexactly(n), timeout=SOCKET_TIMEOUT)
asyncio.StreamReader.read_until = lambda self, s: asyncio.wait_for(self.readuntil(s), timeout=SOCKET_TIMEOUT)

if not hasattr(asyncio.StreamReader, 'readuntil'): # Python 3.4 and below
    @asyncio.coroutine
    def readuntil(self, separator):
        seplen = len(separator)
        offset = 0
        while True:
            buflen = len(self._buffer)
            if buflen - offset >= seplen:
                isep = self._buffer.find(separator, offset)
                if isep != -1:
                    break
                offset = buflen + 1 - seplen
            if self._eof:
                chunk = bytes(self._buffer)
                self._buffer.clear()
                raise asyncio.IncompleteReadError(chunk, None)
            yield from self._wait_for_data('readuntil')
        chunk = self._buffer[:isep + seplen]
        del self._buffer[:isep + seplen]
        self._maybe_resume_transport()
        return bytes(chunk)
    asyncio.StreamReader.readuntil = readuntil

AUTH_TIME = 86400 * 30
class AuthTable(object):
    _auth = {}
    def __init__(self, remote_ip):
        self.remote_ip = remote_ip
    def authed(self):
        return time.time() - self._auth.get(self.remote_ip, 0) <= AUTH_TIME
    def set_authed(self):
        self._auth[self.remote_ip] = time.time()

def proxy_handler(reader, writer, protos, rserver, block, cipher, verbose=DUMMY, modstat=lambda r,h:lambda i:DUMMY, **kwargs):
    try:
        remote_ip = (writer.get_extra_info('peername') or ['local'])[0]
        reader_cipher = cipher(reader, writer)[0] if cipher else None
        lproto, host_name, port, initbuf = yield from proto.parse(protos, reader=reader, writer=writer, authtable=AuthTable(remote_ip), reader_cipher=reader_cipher, sock=writer.get_extra_info('socket'), **kwargs)
        if host_name is None:
            writer.close()
            return
        if block and block(host_name):
            raise Exception('BLOCK ' + host_name)
        roption = next(filter(lambda o: not o.match or o.match(host_name), rserver), None)
        viaproxy = bool(roption)
        if viaproxy:
            verbose('{l.name} {}:{} -> {r.rproto.name} {r.bind}'.format(host_name, port, l=lproto, r=roption))
            wait_connect = roption.connect()
        else:
            verbose('{l.name} {}:{}'.format(host_name, port, l=lproto))
            wait_connect = asyncio.open_connection(host=host_name, port=port)
        try:
            reader_remote, writer_remote = yield from asyncio.wait_for(wait_connect, timeout=SOCKET_TIMEOUT)
        except asyncio.TimeoutError:
            raise Exception('Connection timeout {}'.format(rserver))
        try:
            if viaproxy:
                writer_cipher_r = roption.cipher(reader_remote, writer_remote)[1] if roption.cipher else None
                yield from roption.rproto.connect(reader_remote=reader_remote, writer_remote=writer_remote, rauth=roption.auth, host_name=host_name, port=port, initbuf=initbuf, writer_cipher_r=writer_cipher_r, sock=writer_remote.get_extra_info('socket'))
            else:
                writer_remote.write(initbuf)
        except Exception:
            writer_remote.close()
            raise Exception('Unknown remote protocol')
        m = modstat(remote_ip, host_name)
        asyncio.async(lproto.rchannel(reader_remote, writer, m(2+viaproxy), m(4+viaproxy)))
        asyncio.async(lproto.channel(reader, writer_remote, m(viaproxy), DUMMY))
    except Exception as ex:
        if not isinstance(ex, asyncio.TimeoutError):
            verbose('{} from {}'.format(str(ex) or "Unsupported protocol", remote_ip))
        try: writer.close()
        except Exception: pass

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
        if not hasattr(ssl, 'Purpose'):
            raise argparse.ArgumentTypeError('ssl support is available for Python 3.4 and above')
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
        from pproxy.cipher import get_cipher
        err_str, cipher = get_cipher(cipher)
        if err_str:
            raise argparse.ArgumentTypeError(err_str)
    match = pattern_compile(url.query) if url.query else None
    if loc:
        host, _, port = loc.partition(':')
        port = int(port) if port else 8080
        connect = functools.partial(asyncio.open_connection, host=host, port=port, ssl=sslclient)
        server = functools.partial(asyncio.start_server, host=host, port=port, ssl=sslserver)
    else:
        connect = functools.partial(asyncio.open_unix_connection, path=url.path, ssl=sslclient, server_hostname='' if sslclient else None)
        server = functools.partial(asyncio.start_unix_server, path=url.path, ssl=sslserver)
    return types.SimpleNamespace(protos=protos, rproto=protos[0], cipher=cipher, auth=url.fragment.encode(), match=match, server=server, connect=connect, bind=loc or url.path, sslclient=sslclient, sslserver=sslserver)

def main():
    parser = argparse.ArgumentParser(description=__description__+'\nSupported protocols: http,socks,shadowsocks,redirect', epilog='Online help: <https://github.com/qwj/python-proxy>')
    parser.add_argument('-i', dest='listen', default=[], action='append', type=uri_compile, help='proxy server setting uri (default: http+socks://:8080/)')
    parser.add_argument('-r', dest='rserver', default=[], action='append', type=uri_compile, help='remote server setting uri (default: direct)')
    parser.add_argument('-b', dest='block', type=pattern_compile, help='block regex rules')
    parser.add_argument('-v', dest='v', action='store_true', help='print verbose output')
    parser.add_argument('--ssl', dest='sslfile', help='certfile[,keyfile] if server listen in ssl mode')
    parser.add_argument('--pac', dest='pac', help='http PAC path')
    parser.add_argument('--get', dest='gets', default=[], action='append', help='http custom path/file')
    parser.add_argument('--version', action='version', version='%(prog)s {}'.format(__version__))
    args = parser.parse_args()
    if not args.listen:
        args.listen.append(uri_compile('http+socks://:8080/'))
    args.httpget = {}
    if args.pac:
        pactext = 'function FindProxyForURL(u,h){' + ('var b=/^(:?{})$/i;if(b.test(h))return "";'.format(args.block.__self__.pattern) if args.block else '')
        for i, option in enumerate(args.rserver):
            pactext += ('var m{1}=/^(:?{0})$/i;if(m{1}.test(h))'.format(option.match.__self__.pattern, i) if option.match else '') + 'return "PROXY %(host)s";'
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
        print('You must specify --ssl to listen in ssl mode')
        return
    loop = asyncio.get_event_loop()
    if args.v:
        from pproxy import verbose
        verbose.setup(loop, args)
    servers = []
    for option in args.listen:
        print('Serving on', option.bind, 'by', ",".join(i.name for i in option.protos) + ('(SSL)' if option.sslclient else ''), '({})'.format(option.cipher.name) if option.cipher else '')
        handler = functools.partial(functools.partial(proxy_handler, **vars(args)), **vars(option))
        try:
            server = loop.run_until_complete(option.server(handler))
            servers.append(server)
        except Exception as ex:
            print('Start server failed.\n\t==>', ex)
    if servers:
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

