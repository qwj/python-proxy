import argparse, time, re, asyncio, functools, base64, random, urllib.parse, socket
from . import proto
from .__doc__ import *

SOCKET_TIMEOUT = 300
PACKET_SIZE = 65536
UDP_LIMIT = 30
DUMMY = lambda s: s

asyncio.StreamReader.read_ = lambda self: self.read(PACKET_SIZE)
asyncio.StreamReader.read_n = lambda self, n: asyncio.wait_for(self.readexactly(n), timeout=SOCKET_TIMEOUT)
asyncio.StreamReader.read_until = lambda self, s: asyncio.wait_for(self.readuntil(s), timeout=SOCKET_TIMEOUT)

class AuthTable(object):
    _auth = {}
    def __init__(self, remote_ip, authtime):
        self.remote_ip = remote_ip
        self.authtime = authtime
    def authed(self):
        return time.time() - self._auth.get(self.remote_ip, 0) <= self.authtime
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

def schedule(rserver, salgorithm, host_name):
    filter_cond = lambda o: o.alive and (not o.match or o.match(host_name))
    if salgorithm == 'fa':
        return next(filter(filter_cond, rserver), None)
    elif salgorithm == 'rr':
        for i, roption in enumerate(rserver):
            if filter_cond(roption):
                rserver.append(rserver.pop(i))
                return roption
    elif salgorithm == 'rc':
        filters = [i for i in rserver if filter_cond(i)]
        return random.choice(filters) if filters else None
    elif salgorithm == 'lc':
        return min(filter(filter_cond, rserver), default=None, key=lambda i: i.total)
    else:
        raise Exception('Unknown scheduling algorithm') #Unreachable

async def stream_handler(reader, writer, unix, lbind, protos, rserver, cipher, authtime=86400*30, block=None, salgorithm='fa', verbose=DUMMY, modstat=lambda r,h:lambda i:DUMMY, **kwargs):
    try:
        if unix:
            remote_ip, server_ip, remote_text = 'local', None, 'unix_local'
        else:
            remote_ip, remote_port, *_ = writer.get_extra_info('peername')
            server_ip = writer.get_extra_info('sockname')[0]
            remote_text = f'{remote_ip}:{remote_port}'
        local_addr = None if server_ip in ('127.0.0.1', '::1', None) else (server_ip, 0)
        reader_cipher, _ = await prepare_ciphers(cipher, reader, writer, server_side=False)
        lproto, host_name, port, initbuf = await proto.parse(protos, reader=reader, writer=writer, authtable=AuthTable(remote_ip, authtime), reader_cipher=reader_cipher, sock=writer.get_extra_info('socket'), **kwargs)
        if host_name == 'echo':
            asyncio.ensure_future(lproto.channel(reader, writer, DUMMY, DUMMY))
        elif host_name == 'empty':
            asyncio.ensure_future(lproto.channel(reader, writer, None, DUMMY))
        elif block and block(host_name):
            raise Exception('BLOCK ' + host_name)
        else:
            roption = schedule(rserver, salgorithm, host_name) or ProxyURI.DIRECT
            verbose(f'{lproto.name} {remote_text}{roption.logtext(host_name, port)}')
            try:
                reader_remote, writer_remote = await roption.open_connection(host_name, port, local_addr, lbind)
            except asyncio.TimeoutError:
                raise Exception(f'Connection timeout {roption.bind}')
            try:
                reader_remote, writer_remote = await roption.prepare_connection(reader_remote, writer_remote, host_name, port)
                writer_remote.write(initbuf)
            except Exception:
                writer_remote.close()
                raise Exception('Unknown remote protocol')
            m = modstat(remote_ip, host_name)
            lchannel = lproto.http_channel if initbuf else lproto.channel
            asyncio.ensure_future(lproto.channel(reader_remote, writer, m(2+roption.direct), m(4+roption.direct)))
            asyncio.ensure_future(lchannel(reader, writer_remote, m(roption.direct), roption.connection_change))
    except Exception as ex:
        if not isinstance(ex, asyncio.TimeoutError) and not str(ex).startswith('Connection closed'):
            verbose(f'{str(ex) or "Unsupported protocol"} from {remote_ip}')
        try: writer.close()
        except Exception: pass

async def reuse_stream_handler(reader, writer, unix, lbind, protos, rserver, urserver, block, cipher, salgorithm, verbose=DUMMY, modstat=lambda r,h:lambda i:DUMMY, **kwargs):
    try:
        if unix:
            remote_ip, server_ip, remote_text = 'local', None, 'unix_local'
        else:
            remote_ip, remote_port, *_ = writer.get_extra_info('peername')
            server_ip = writer.get_extra_info('sockname')[0]
            remote_text = f'{remote_ip}:{remote_port}'
        local_addr = None if server_ip in ('127.0.0.1', '::1', None) else (server_ip, 0)
        reader_cipher, _ = await prepare_ciphers(cipher, reader, writer, server_side=False)
        lproto = protos[0]
    except Exception as ex:
        verbose(f'{str(ex) or "Unsupported protocol"} from {remote_ip}')
    async def tcp_handler(reader, writer, host_name, port):
        try:
            if block and block(host_name):
                raise Exception('BLOCK ' + host_name)
            roption = schedule(rserver, salgorithm, host_name) or ProxyURI.DIRECT
            verbose(f'{lproto.name} {remote_text}{roption.logtext(host_name, port)}')
            try:
                reader_remote, writer_remote = await roption.open_connection(host_name, port, local_addr, lbind)
            except asyncio.TimeoutError:
                raise Exception(f'Connection timeout {roption.bind}')
            try:
                reader_remote, writer_remote = await roption.prepare_connection(reader_remote, writer_remote, host_name, port)
            except Exception:
                writer_remote.close()
                raise Exception('Unknown remote protocol')
            m = modstat(remote_ip, host_name)
            asyncio.ensure_future(lproto.channel(reader_remote, writer, m(2+roption.direct), m(4+roption.direct)))
            asyncio.ensure_future(lproto.channel(reader, writer_remote, m(roption.direct), roption.connection_change))
        except Exception as ex:
            if not isinstance(ex, asyncio.TimeoutError) and not str(ex).startswith('Connection closed'):
                verbose(f'{str(ex) or "Unsupported protocol"} from {remote_ip}')
            try: writer.close()
            except Exception: pass
    async def udp_handler(sendto, data, host_name, port, sid):
        try:
            if block and block(host_name):
                raise Exception('BLOCK ' + host_name)
            roption = schedule(urserver, salgorithm, host_name) or ProxyURI.DIRECT
            verbose(f'UDP {lproto.name} {remote_text}{roption.logtext(host_name, port)}')
            data = roption.prepare_udp_connection(host_name, port, data)
            await roption.open_udp_connection(host_name, port, data, sid, sendto)
        except Exception as ex:
            if not str(ex).startswith('Connection closed'):
                verbose(f'{str(ex) or "Unsupported protocol"} from {remote_ip}')
    lproto.get_handler(reader, writer, verbose, tcp_handler, udp_handler)

async def datagram_handler(writer, data, addr, protos, urserver, block, cipher, salgorithm, verbose=DUMMY, **kwargs):
    try:
        remote_ip, remote_port, *_ = addr
        remote_text = f'{remote_ip}:{remote_port}'
        data = cipher.datagram.decrypt(data) if cipher else data
        lproto, host_name, port, data = proto.udp_parse(protos, data, sock=writer.get_extra_info('socket'), **kwargs)
        if host_name == 'echo':
            writer.sendto(data, addr)
        elif host_name == 'empty':
            pass
        elif block and block(host_name):
            raise Exception('BLOCK ' + host_name)
        else:
            roption = schedule(urserver, salgorithm, host_name) or ProxyURI.DIRECT
            verbose(f'UDP {lproto.name} {remote_text}{roption.logtext(host_name, port)}')
            data = roption.prepare_udp_connection(host_name, port, data)
            def reply(rdata):
                rdata = lproto.udp_client2(host_name, port, rdata)
                writer.sendto(cipher.datagram.encrypt(rdata) if cipher else rdata, addr)
            await roption.open_udp_connection(host_name, port, data, addr, reply)
    except Exception as ex:
        if not str(ex).startswith('Connection closed'):
            verbose(f'{str(ex) or "Unsupported protocol"} from {remote_ip}')

async def check_server_alive(interval, rserver, verbose):
    while True:
        await asyncio.sleep(interval)
        for remote in rserver:
            if remote.direct:
                continue
            try:
                _, writer = await remote.open_connection(None, None, None, None)
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

class BackwardConnection(object):
    def __init__(self, uri):
        self.uri = uri
        self.closed = False
        self.conn = asyncio.Queue()
        self.open_connection = self.conn.get
    def close(self):
        self.closed = True
        try:
            self.writer.close()
        except Exception:
            pass
    async def start_server(self, handler):
        asyncio.ensure_future(self.server_run(handler))
        return self
    async def server_run(self, handler):
        errwait = 0
        while not self.closed:
            if self.uri.unix:
                wait = asyncio.open_unix_connection(path=self.uri.bind, ssl=self.uri.sslclient, server_hostname='' if self.uri.sslclient else None)
            else:
                wait = asyncio.open_connection(host=self.uri.host_name, port=self.uri.port, ssl=self.uri.sslclient, local_addr=(self.uri.lbind, 0) if self.uri.lbind else None)
            try:
                reader, writer = await asyncio.wait_for(wait, timeout=SOCKET_TIMEOUT)
                self.writer = writer
                try:
                    data = await reader.read_n(1)
                except asyncio.TimeoutError:
                    data = None
                if data:
                    reader._buffer[0:0] = data
                    asyncio.ensure_future(handler(reader, writer))
                else:
                    writer.close()
                errwait = 0
            except Exception as ex:
                try:
                    writer.close()
                except Exception:
                    pass
                if not self.closed:
                    await asyncio.sleep(errwait)
                    errwait = min(errwait*1.3 + 0.1, 30)
    def client_run(self):
        async def handler(reader, writer):
            while not self.conn.empty():
                r, w = await self.conn.get()
                try: w.close()
                except Exception: pass
            await self.conn.put((reader, writer))
        if self.uri.unix:
            return asyncio.start_unix_server(handler, path=self.uri.bind, ssl=self.uri.sslserver)
        else:
            return asyncio.start_server(handler, host=self.uri.host_name, port=self.uri.port, ssl=self.uri.sslserver)

class ProxyURI(object):
    def __init__(self, **kw):
        self.__dict__.update(kw)
        self.total = 0
        self.udpmap = {}
        self.handler = None
        self.streams = None
        if self.backward:
            self.backward = BackwardConnection(self)
    def logtext(self, host, port):
        if self.direct:
            return f' -> {host}:{port}'
        elif self.tunnel:
            return f' ->{(" ssl" if self.sslclient else "")} {self.bind}'
        else:
            return f' -> {self.rproto.name+("+ssl" if self.sslclient else "")} {self.bind}' + self.relay.logtext(host, port)
    def connection_change(self, delta):
        self.total += delta
    async def open_udp_connection(self, host, port, data, addr, reply):
        class Protocol(asyncio.DatagramProtocol):
            def __init__(prot, data):
                self.udpmap[addr] = prot
                prot.databuf = [data]
                prot.transport = None
                prot.update = 0
            def connection_made(prot, transport):
                prot.transport = transport
                for data in prot.databuf:
                    transport.sendto(data)
                prot.databuf.clear()
                prot.update = time.perf_counter()
            def new_data_arrived(prot, data):
                if prot.transport:
                    prot.transport.sendto(data)
                else:
                    prot.databuf.append(data)
                prot.update = time.perf_counter()
            def datagram_received(prot, data, addr):
                data = self.cipher.datagram.decrypt(data) if self.cipher else data
                data = self.rproto.udp_client(data) if not self.direct else data
                reply(data)
                prot.update = time.perf_counter()
            def connection_lost(prot, exc):
                self.udpmap.pop(addr, None)
        if addr in self.udpmap:
            self.udpmap[addr].new_data_arrived(data)
        else:
            if self.direct and host == 'tunnel':
                raise Exception('Unknown tunnel endpoint')
            self.connection_change(1)
            if len(self.udpmap) > UDP_LIMIT:
                min_addr = min(self.udpmap, key=lambda x: self.udpmap[x].update)
                prot = self.udpmap.pop(min_addr)
                if prot.transport:
                    prot.transport.close()
            prot = Protocol(data)
            remote_addr = (host, port) if self.direct else (self.host_name, self.port)
            await asyncio.get_event_loop().create_datagram_endpoint(lambda: prot, remote_addr=remote_addr)
    def prepare_udp_connection(self, host, port, data):
        if not self.direct:
            data = self.relay.prepare_udp_connection(host, port, data)
            whost, wport = (host, port) if self.relay.direct else (self.relay.host_name, self.relay.port)
            data = self.rproto.udp_connect(rauth=self.auth, host_name=whost, port=wport, data=data)
            if self.cipher:
                data = self.cipher.datagram.encrypt(data)
        return data
    def start_udp_server(self, args):
        class Protocol(asyncio.DatagramProtocol):
            def connection_made(prot, transport):
                prot.transport = transport
            def datagram_received(prot, data, addr):
                asyncio.ensure_future(datagram_handler(prot.transport, data, addr, **vars(self), **args))
        return asyncio.get_event_loop().create_datagram_endpoint(Protocol, local_addr=(self.host_name, self.port))
    async def open_connection(self, host, port, local_addr, lbind):
        if self.reuse or self.ssh:
            if self.streams is None or self.streams.done() and (self.reuse and not self.handler):
                self.streams = asyncio.get_event_loop().create_future()
            else:
                if not self.streams.done():
                    await self.streams
                return self.streams.result()
        try:
            local_addr = local_addr if self.lbind == 'in' else (self.lbind, 0) if self.lbind else \
                         local_addr if lbind == 'in' else (lbind, 0) if lbind else None
            family = 0 if local_addr is None else socket.AF_INET6 if ':' in local_addr[0] else socket.AF_INET
            if self.direct:
                if host == 'tunnel':
                    raise Exception('Unknown tunnel endpoint')
                wait = asyncio.open_connection(host=host, port=port, local_addr=local_addr, family=family)
            elif self.ssh:
                try:
                    import asyncssh
                    for s in ('read_', 'read_n', 'read_until'):
                        setattr(asyncssh.SSHReader, s, getattr(asyncio.StreamReader, s))
                except Exception:
                    raise Exception('Missing library: "pip3 install asyncssh"')
                username, password = self.auth.decode().split(':', 1)
                if password.startswith(':'):
                    client_keys = [password[1:]]
                    password = None
                else:
                    client_keys = None
                conn = await asyncssh.connect(host=self.host_name, port=self.port, local_addr=local_addr, family=family, x509_trusted_certs=None, known_hosts=None, username=username, password=password, client_keys=client_keys)
                if not self.streams.done():
                    self.streams.set_result((conn, None))
                return conn, None
            elif self.backward:
                wait = self.backward.open_connection()
            elif self.unix:
                wait = asyncio.open_unix_connection(path=self.bind, ssl=self.sslclient, server_hostname='' if self.sslclient else None)
            else:
                wait = asyncio.open_connection(host=self.host_name, port=self.port, ssl=self.sslclient, local_addr=local_addr, family=family)
            reader, writer = await asyncio.wait_for(wait, timeout=SOCKET_TIMEOUT)
        except Exception as ex:
            if self.reuse:
                self.streams.set_exception(ex)
                self.streams = None
            raise
        return reader, writer
    def prepare_connection(self, reader_remote, writer_remote, host, port):
        if self.reuse and not self.handler:
            self.handler = self.rproto.get_handler(reader_remote, writer_remote, DUMMY)
        return self.prepare_ciphers_and_headers(reader_remote, writer_remote, host, port, self.handler)
    async def prepare_ciphers_and_headers(self, reader_remote, writer_remote, host, port, handler):
        if not self.direct:
            if not handler or not handler.ready:
                _, writer_cipher_r = await prepare_ciphers(self.cipher, reader_remote, writer_remote, self.bind)
            else:
                writer_cipher_r = None
            whost, wport = (host, port) if self.relay.direct else (self.relay.host_name, self.relay.port)
            if self.rproto.reuse():
                if not self.streams.done():
                    self.streams.set_result((reader_remote, writer_remote))
                reader_remote, writer_remote = handler.connect(whost, wport)
            elif self.ssh:
                reader_remote, writer_remote = await reader_remote.open_connection(whost, wport)
            else:
                await self.rproto.connect(reader_remote=reader_remote, writer_remote=writer_remote, rauth=self.auth, host_name=whost, port=wport, writer_cipher_r=writer_cipher_r, myhost=self.host_name, sock=writer_remote.get_extra_info('socket'))
            return await self.relay.prepare_ciphers_and_headers(reader_remote, writer_remote, host, port, handler)
        return reader_remote, writer_remote
    def start_server(self, args):
        handler = functools.partial(reuse_stream_handler if self.reuse else stream_handler, **vars(self), **args)
        if self.backward:
            return self.backward.start_server(handler)
        elif self.unix:
            return asyncio.start_unix_server(handler, path=self.bind, ssl=self.sslserver)
        else:
            return asyncio.start_server(handler, host=self.host_name, port=self.port, ssl=self.sslserver, reuse_port=args.get('ruport'))
    async def tcp_connect(self, host, port, local_addr=None, lbind=None):
        reader, writer = await self.open_connection(host, port, local_addr, lbind)
        try:
            reader, writer = await self.prepare_connection(reader, writer, host, port)
        except Exception:
            writer.close()
            raise
        return reader, writer
    async def udp_sendto(self, host, port, data, answer_cb, local_addr=None):
        if local_addr is None:
            local_addr = random.randrange(2**32)
        data = self.prepare_udp_connection(host, port, data)
        await self.open_udp_connection(host, port, data, local_addr, answer_cb)
    @classmethod
    def compile_rule(cls, filename):
        with open(filename) as f:
            return re.compile('(:?'+''.join('|'.join(i.strip() for i in f if i.strip() and not i.startswith('#')))+')$').match
    @classmethod
    def compile_relay(cls, uri):
        tail = cls.DIRECT
        for urip in reversed(uri.split('__')):
            tail = cls.compile(urip, tail)
        return tail
    @classmethod
    def compile(cls, uri, relay=None):
        scheme, _, uri = uri.partition('://')
        url = urllib.parse.urlparse('s://'+uri)
        rawprotos = scheme.split('+')
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
            sslserver = sslclient = None
        protonames = [i.name for i in protos]
        if 'pack' in protonames and relay and relay != cls.DIRECT:
            raise argparse.ArgumentTypeError('pack protocol cannot relay to other proxy')
        urlpath, _, plugins = url.path.partition(',')
        urlpath, _, lbind = urlpath.partition('@')
        plugins = plugins.split(',') if plugins else None
        cipher, _, loc = url.netloc.rpartition('@')
        if cipher:
            from .cipher import get_cipher
            if ':' not in cipher:
                try:
                    cipher = base64.b64decode(cipher).decode()
                except Exception:
                    pass
                if ':' not in cipher:
                    raise argparse.ArgumentTypeError('userinfo must be "cipher:key"')
            err_str, cipher = get_cipher(cipher)
            if err_str:
                raise argparse.ArgumentTypeError(err_str)
            if plugins:
                from .plugin import get_plugin
                for name in plugins:
                    if not name: continue
                    err_str, plugin = get_plugin(name)
                    if err_str:
                        raise argparse.ArgumentTypeError(err_str)
                    cipher.plugins.append(plugin)
        match = cls.compile_rule(url.query) if url.query else None
        if loc:
            host_name, _, port = loc.partition(':')
            port = int(port) if port else (22 if 'ssh' in rawprotos else 8080)
        else:
            host_name = port = None
        return ProxyURI(protos=protos, rproto=protos[0], cipher=cipher, auth=url.fragment.encode(), \
                        match=match, bind=loc or urlpath, host_name=host_name, port=port, \
                        unix=not loc, lbind=lbind, sslclient=sslclient, sslserver=sslserver, \
                        alive=True, direct='direct' in protonames, tunnel='tunnel' in protonames, \
                        reuse='pack' in protonames or relay and relay.reuse, backward='in' in rawprotos, \
                        ssh='ssh' in rawprotos, relay=relay)
ProxyURI.DIRECT = ProxyURI(direct=True, tunnel=False, reuse=False, relay=None, alive=True, match=None, cipher=None, backward=None, ssh=None)

async def test_url(url, rserver):
    url = urllib.parse.urlparse(url)
    assert url.scheme in ('http', ), f'Unknown scheme {url.scheme}'
    host_name, _, port = url.netloc.partition(':')
    port = int(port) if port else 80 if url.scheme == 'http' else 443
    initbuf = f'GET {url.path or "/"} HTTP/1.1\r\nHost: {host_name}\r\nUser-Agent: pproxy-{__version__}\r\nConnection: close\r\n\r\n'.encode()
    for roption in rserver:
        print(f'============ {roption.bind} ============')
        try:
            reader, writer = await roption.open_connection(host_name, port, None, None)
        except asyncio.TimeoutError:
            raise Exception(f'Connection timeout {rserver}')
        try:
            reader, writer = await roption.prepare_connection(reader, writer, host_name, port)
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
    parser = argparse.ArgumentParser(description=__description__+'\nSupported protocols: http,socks4,socks5,shadowsocks,shadowsocksr,redirect,pf,tunnel', epilog=f'Online help: <{__url__}>')
    parser.add_argument('-l', dest='listen', default=[], action='append', type=ProxyURI.compile, help='tcp server uri (default: http+socks4+socks5://:8080/)')
    parser.add_argument('-r', dest='rserver', default=[], action='append', type=ProxyURI.compile_relay, help='tcp remote server uri (default: direct)')
    parser.add_argument('-ul', dest='ulisten', default=[], action='append', type=ProxyURI.compile, help='udp server setting uri (default: none)')
    parser.add_argument('-ur', dest='urserver', default=[], action='append', type=ProxyURI.compile_relay, help='udp remote server uri (default: direct)')
    parser.add_argument('-b', dest='block', type=ProxyURI.compile_rule, help='block regex rules')
    parser.add_argument('-a', dest='alived', default=0, type=int, help='interval to check remote alive (default: no check)')
    parser.add_argument('-s', dest='salgorithm', default='fa', choices=('fa', 'rr', 'rc', 'lc'), help='scheduling algorithm (default: first_available)')
    parser.add_argument('-v', dest='v', action='count', help='print verbose output')
    parser.add_argument('--ssl', dest='sslfile', help='certfile[,keyfile] if server listen in ssl mode')
    parser.add_argument('--pac', help='http PAC path')
    parser.add_argument('--get', dest='gets', default=[], action='append', help='http custom {path,file}')
    parser.add_argument('--auth', dest='authtime', type=int, default=86400*30, help='re-auth time interval for same ip (default: 86400*30)')
    parser.add_argument('--sys', action='store_true', help='change system proxy setting (mac, windows)')
    parser.add_argument('--reuse', dest='ruport', action='store_true', help='set SO_REUSEPORT (Linux only)')
    parser.add_argument('--test', help='test this url for all remote proxies and exit')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    args = parser.parse_args()
    if args.test:
        asyncio.get_event_loop().run_until_complete(test_url(args.test, args.rserver))
        return
    if not args.listen and not args.ulisten:
        args.listen.append(ProxyURI.compile_relay('http+socks4+socks5://:8080/'))
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
        from . import verbose
        verbose.setup(loop, args)
    servers = []
    for option in args.listen:
        print('Serving on', option.bind, 'by', ",".join(i.name for i in option.protos) + ('(SSL)' if option.sslclient else ''), '({}{})'.format(option.cipher.name, ' '+','.join(i.name() for i in option.cipher.plugins) if option.cipher and option.cipher.plugins else '') if option.cipher else '')
        try:
            server = loop.run_until_complete(option.start_server(vars(args)))
            servers.append(server)
        except Exception as ex:
            print('Start server failed.\n\t==>', ex)
    for option in args.ulisten:
        print('Serving on UDP', option.bind, 'by', ",".join(i.name for i in option.protos), f'({option.cipher.name})' if option.cipher else '')
        try:
            server, protocol = loop.run_until_complete(option.start_udp_server(vars(args)))
            servers.append(server)
        except Exception as ex:
            print('Start server failed.\n\t==>', ex)
    for option in args.rserver:
        if option.backward:
            print('Serving on', option.bind, 'backward by', ",".join(i.name for i in option.protos) + ('(SSL)' if option.sslclient else ''), '({}{})'.format(option.cipher.name, ' '+','.join(i.name() for i in option.cipher.plugins) if option.cipher and option.cipher.plugins else '') if option.cipher else '')
            try:
                server = loop.run_until_complete(option.backward.client_run())
                servers.append(server)
            except Exception as ex:
                print('Start server failed.\n\t==>', ex)
    if servers:
        if args.sys:
            from . import sysproxy
            args.sys = sysproxy.setup(args)
        if args.alived > 0 and args.rserver:
            asyncio.ensure_future(check_server_alive(args.alived, args.rserver, args.verbose if args.v else DUMMY))
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            print('exit')
        if args.sys:
            args.sys.clear()
    for task in asyncio.Task.all_tasks():
        task.cancel()
    for server in servers:
        server.close()
    for server in servers:
        if hasattr(server, 'wait_closed'):
            loop.run_until_complete(server.wait_closed())
    loop.run_until_complete(loop.shutdown_asyncgens())
    loop.close()

if __name__ == '__main__':
    main()
