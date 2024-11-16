import argparse, time, re, asyncio, functools, base64, random, urllib.parse, socket, sys
from . import proto
from . import admin

from .__doc__ import *

SOCKET_TIMEOUT = 60
UDP_LIMIT = 30
DUMMY = lambda s: s

def patch_StreamReader(c=asyncio.StreamReader):
    c.read_w = lambda self, n: asyncio.wait_for(self.read(n), timeout=SOCKET_TIMEOUT)
    c.read_n = lambda self, n: asyncio.wait_for(self.readexactly(n), timeout=SOCKET_TIMEOUT)
    c.read_until = lambda self, s: asyncio.wait_for(self.readuntil(s), timeout=SOCKET_TIMEOUT)
    c.rollback = lambda self, s: self._buffer.__setitem__(slice(0, 0), s)
def patch_StreamWriter(c=asyncio.StreamWriter):
    c.is_closing = lambda self: self._transport.is_closing() # Python 3.6 fix
patch_StreamReader()
patch_StreamWriter()

class AuthTable(object):
    _auth = {}
    _user = {}
    def __init__(self, remote_ip, authtime):
        self.remote_ip = remote_ip
        self.authtime = authtime
    def authed(self):
        if time.time() - self._auth.get(self.remote_ip, 0) <= self.authtime:
            return self._user[self.remote_ip]
    def set_authed(self, user):
        self._auth[self.remote_ip] = time.time()
        self._user[self.remote_ip] = user

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

def schedule(rserver, salgorithm, host_name, port):
    filter_cond = lambda o: o.alive and o.match_rule(host_name, port)
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
        return min(filter(filter_cond, rserver), default=None, key=lambda i: i.connections)
    else:
        raise Exception('Unknown scheduling algorithm') #Unreachable

async def stream_handler(reader, writer, unix, lbind, protos, rserver, cipher, sslserver, debug=0, authtime=86400*30, block=None, salgorithm='fa', verbose=DUMMY, modstat=lambda u,r,h:lambda i:DUMMY, **kwargs):
    try:
        reader, writer = proto.sslwrap(reader, writer, sslserver, True, None, verbose)
        if unix:
            remote_ip, server_ip, remote_text = 'local', None, 'unix_local'
        else:
            peername = writer.get_extra_info('peername')
            remote_ip, remote_port, *_ = peername if peername else ('unknow_remote_ip','unknow_remote_port')
            server_ip = writer.get_extra_info('sockname')[0]
            remote_text = f'{remote_ip}:{remote_port}'
        local_addr = None if server_ip in ('127.0.0.1', '::1', None) else (server_ip, 0)
        reader_cipher, _ = await prepare_ciphers(cipher, reader, writer, server_side=False)
        lproto, user, host_name, port, client_connected = await proto.accept(protos, reader=reader, writer=writer, authtable=AuthTable(remote_ip, authtime), reader_cipher=reader_cipher, sock=writer.get_extra_info('socket'), **kwargs)
        if host_name == 'echo':
            asyncio.ensure_future(lproto.channel(reader, writer, DUMMY, DUMMY))
        elif host_name == 'empty':
            asyncio.ensure_future(lproto.channel(reader, writer, None, DUMMY))
        elif block and block(host_name):
            raise Exception('BLOCK ' + host_name)
        else:
            roption = schedule(rserver, salgorithm, host_name, port) or DIRECT
            verbose(f'{lproto.name} {remote_text}{roption.logtext(host_name, port)}')
            try:
                reader_remote, writer_remote = await roption.open_connection(host_name, port, local_addr, lbind)
            except asyncio.TimeoutError:
                raise Exception(f'Connection timeout {roption.bind}')
            try:
                reader_remote, writer_remote = await roption.prepare_connection(reader_remote, writer_remote, host_name, port)
                use_http = (await client_connected(writer_remote)) if client_connected else None
            except Exception:
                writer_remote.close()
                raise Exception('Unknown remote protocol')
            m = modstat(user, remote_ip, host_name)
            lchannel = lproto.http_channel if use_http else lproto.channel
            asyncio.ensure_future(lproto.channel(reader_remote, writer, m(2+roption.direct), m(4+roption.direct)))
            asyncio.ensure_future(lchannel(reader, writer_remote, m(roption.direct), roption.connection_change))
    except Exception as ex:
        if not isinstance(ex, asyncio.TimeoutError) and not str(ex).startswith('Connection closed'):
            verbose(f'{str(ex) or "Unsupported protocol"} from {remote_ip}')
        try: writer.close()
        except Exception: pass
        if debug:
            raise

async def datagram_handler(writer, data, addr, protos, urserver, block, cipher, salgorithm, verbose=DUMMY, **kwargs):
    try:
        remote_ip, remote_port, *_ = addr
        remote_text = f'{remote_ip}:{remote_port}'
        data = cipher.datagram.decrypt(data) if cipher else data
        lproto, user, host_name, port, data = proto.udp_accept(protos, data, sock=writer.get_extra_info('socket'), **kwargs)
        if host_name == 'echo':
            writer.sendto(data, addr)
        elif host_name == 'empty':
            pass
        elif block and block(host_name):
            raise Exception('BLOCK ' + host_name)
        else:
            roption = schedule(urserver, salgorithm, host_name, port) or DIRECT
            verbose(f'UDP {lproto.name} {remote_text}{roption.logtext(host_name, port)}')
            data = roption.udp_prepare_connection(host_name, port, data)
            def reply(rdata):
                rdata = lproto.udp_pack(host_name, port, rdata)
                writer.sendto(cipher.datagram.encrypt(rdata) if cipher else rdata, addr)
            await roption.udp_open_connection(host_name, port, data, addr, reply)
    except Exception as ex:
        if not str(ex).startswith('Connection closed'):
            verbose(f'{str(ex) or "Unsupported protocol"} from {remote_ip}')

async def check_server_alive(interval, rserver, verbose):
    while True:
        await asyncio.sleep(interval)
        for remote in rserver:
            if type(remote) is ProxyDirect:
                continue
            try:
                _, writer = await remote.open_connection(None, None, None, None, timeout=3)
            except asyncio.CancelledError as ex:
                return
            except Exception as ex:
                if remote.alive:
                    verbose(f'{remote.rproto.name} {remote.bind} -> OFFLINE')
                    remote.alive = False
                continue
            if not remote.alive:
                verbose(f'{remote.rproto.name} {remote.bind} -> ONLINE')
                remote.alive = True
            try:
                if isinstance(remote, ProxyBackward):
                    writer.write(b'\x00')
                writer.close()
            except Exception:
                pass

class ProxyDirect(object):
    def __init__(self, lbind=None):
        self.bind = 'DIRECT'
        self.lbind = lbind
        self.unix = False
        self.alive = True
        self.connections = 0
        self.udpmap = {}
    @property
    def direct(self):
        return type(self) is ProxyDirect
    def logtext(self, host, port):
        return '' if host == 'tunnel' else f' -> {host}:{port}'
    def match_rule(self, host, port):
        return True
    def connection_change(self, delta):
        self.connections += delta
    def udp_packet_unpack(self, data):
        return data
    def destination(self, host, port):
        return host, port
    async def udp_open_connection(self, host, port, data, addr, reply):
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
                data = self.udp_packet_unpack(data)
                reply(data)
                prot.update = time.perf_counter()
            def connection_lost(prot, exc):
                self.udpmap.pop(addr, None)
        if addr in self.udpmap:
            self.udpmap[addr].new_data_arrived(data)
        else:
            self.connection_change(1)
            if len(self.udpmap) > UDP_LIMIT:
                min_addr = min(self.udpmap, key=lambda x: self.udpmap[x].update)
                prot = self.udpmap.pop(min_addr)
                if prot.transport:
                    prot.transport.close()
            prot = lambda: Protocol(data)
            remote = self.destination(host, port)
            await asyncio.get_event_loop().create_datagram_endpoint(prot, remote_addr=remote)
    def udp_prepare_connection(self, host, port, data):
        return data
    def wait_open_connection(self, host, port, local_addr, family):
        return asyncio.open_connection(host=host, port=port, local_addr=local_addr, family=family)
    async def open_connection(self, host, port, local_addr, lbind, timeout=SOCKET_TIMEOUT):
        try:
            local_addr = local_addr if self.lbind == 'in' else (self.lbind, 0) if self.lbind else \
                         local_addr if lbind == 'in' else (lbind, 0) if lbind else None
            family = 0 if local_addr is None else socket.AF_INET6 if ':' in local_addr[0] else socket.AF_INET
            wait = self.wait_open_connection(host, port, local_addr, family)
            reader, writer = await asyncio.wait_for(wait, timeout=timeout)
        except Exception as ex:
            raise
        return reader, writer
    async def prepare_connection(self, reader_remote, writer_remote, host, port):
        return reader_remote, writer_remote
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
        data = self.udp_prepare_connection(host, port, data)
        await self.udp_open_connection(host, port, data, local_addr, answer_cb)
DIRECT = ProxyDirect()

class ProxySimple(ProxyDirect):
    def __init__(self, jump, protos, cipher, users, rule, bind,
                  host_name, port, unix, lbind, sslclient, sslserver):
        super().__init__(lbind)
        self.protos = protos
        self.cipher = cipher
        self.users = users
        self.rule = compile_rule(rule) if rule else None
        self.bind = bind
        self.host_name = host_name
        self.port = port
        self.unix = unix
        self.sslclient = sslclient
        self.sslserver = sslserver
        self.jump = jump
    def logtext(self, host, port):
        return f' -> {self.rproto.name+("+ssl" if self.sslclient else "")} {self.bind}' + self.jump.logtext(host, port)
    def match_rule(self, host, port):
        return (self.rule is None) or self.rule(host) or self.rule(str(port))
    @property
    def rproto(self):
        return self.protos[0]
    @property
    def auth(self):
        return self.users[0] if self.users else b''
    def udp_packet_unpack(self, data):
        data = self.cipher.datagram.decrypt(data) if self.cipher else data
        return self.jump.udp_packet_unpack(self.rproto.udp_unpack(data))
    def destination(self, host, port):
        return self.host_name, self.port if self.port != 0 else port
    def udp_prepare_connection(self, host, port, data):
        data = self.jump.udp_prepare_connection(host, port, data)
        whost, wport = self.jump.destination(host, port)
        data = self.rproto.udp_connect(rauth=self.auth, host_name=whost, port=wport, data=data)
        if self.cipher:
            data = self.cipher.datagram.encrypt(data)
        return data
    def udp_start_server(self, args):
        class Protocol(asyncio.DatagramProtocol):
            def connection_made(prot, transport):
                prot.transport = transport
            def datagram_received(prot, data, addr):
                asyncio.ensure_future(datagram_handler(prot.transport, data, addr, **vars(self), **args))
        return asyncio.get_event_loop().create_datagram_endpoint(Protocol, local_addr=(self.host_name, self.port))
    def wait_open_connection(self, host, port, local_addr, family):
        if self.unix:
            return asyncio.open_unix_connection(path=self.bind)
        else:
            return asyncio.open_connection(host=self.host_name, port=self.port if self.port != 0 else port, local_addr=local_addr, family=family)
    async def prepare_connection(self, reader_remote, writer_remote, host, port):
        reader_remote, writer_remote = proto.sslwrap(reader_remote, writer_remote, self.sslclient, False, self.host_name)
        _, writer_cipher_r = await prepare_ciphers(self.cipher, reader_remote, writer_remote, self.bind)
        whost, wport = self.jump.destination(host, port)
        await self.rproto.connect(reader_remote=reader_remote, writer_remote=writer_remote, rauth=self.auth, host_name=whost, port=wport, writer_cipher_r=writer_cipher_r, myhost=self.host_name, sock=writer_remote.get_extra_info('socket'))
        return await self.jump.prepare_connection(reader_remote, writer_remote, host, port)
    def start_server(self, args, stream_handler=stream_handler):
        handler = functools.partial(stream_handler, **vars(self), **args)
        if self.unix:
            return asyncio.start_unix_server(handler, path=self.bind)
        else:
            return asyncio.start_server(handler, host=self.host_name, port=self.port, reuse_port=args.get('ruport'))

class ProxyH2(ProxySimple):
    def __init__(self, sslserver, sslclient, **kw):
        super().__init__(sslserver=None, sslclient=None, **kw)
        self.handshake = None
        self.h2sslserver = sslserver
        self.h2sslclient = sslclient
    async def handler(self, reader, writer, client_side=True, stream_handler=None, **kw):
        import h2.connection, h2.config, h2.events
        reader, writer = proto.sslwrap(reader, writer, self.h2sslclient if client_side else self.h2sslserver, not client_side, None)
        config = h2.config.H2Configuration(client_side=client_side)
        conn = h2.connection.H2Connection(config=config)
        streams = {}
        conn.initiate_connection()
        writer.write(conn.data_to_send())
        while not reader.at_eof() and not writer.is_closing():
            try:
                data = await reader.read(65636)
                if not data:
                    break
                events = conn.receive_data(data)
            except Exception:
                pass
            writer.write(conn.data_to_send())
            for event in events:
                if isinstance(event, h2.events.RequestReceived) and not client_side:
                    if event.stream_id not in streams:
                        stream_reader, stream_writer = self.get_stream(conn, writer, event.stream_id)
                        streams[event.stream_id] = (stream_reader, stream_writer)
                        asyncio.ensure_future(stream_handler(stream_reader, stream_writer))
                    else:
                        stream_reader, stream_writer = streams[event.stream_id]
                    stream_writer.headers.set_result(event.headers)
                elif isinstance(event, h2.events.SettingsAcknowledged) and client_side:
                    self.handshake.set_result((conn, streams, writer))
                elif isinstance(event, h2.events.DataReceived):
                    stream_reader, stream_writer = streams[event.stream_id]
                    stream_reader.feed_data(event.data)
                    conn.acknowledge_received_data(len(event.data), event.stream_id)
                    writer.write(conn.data_to_send())
                elif isinstance(event, h2.events.StreamEnded) or isinstance(event, h2.events.StreamReset):
                    stream_reader, stream_writer = streams[event.stream_id]
                    stream_reader.feed_eof()
                    if not stream_writer.closed:
                        stream_writer.close()
                elif isinstance(event, h2.events.ConnectionTerminated):
                    break
                elif isinstance(event, h2.events.WindowUpdated):
                    if event.stream_id in streams:
                        stream_reader, stream_writer = streams[event.stream_id]
                        stream_writer.window_update()
        writer.write(conn.data_to_send())
        writer.close()
    def get_stream(self, conn, writer, stream_id):
        reader = asyncio.StreamReader()
        write_buffer = bytearray()
        write_wait = asyncio.Event()
        write_full = asyncio.Event()
        class StreamWriter():
            def __init__(self):
                self.closed = False
                self.headers = asyncio.get_event_loop().create_future()
            def get_extra_info(self, key):
                return writer.get_extra_info(key)
            def write(self, data):
                write_buffer.extend(data)
                write_wait.set()
            def drain(self):
                writer.write(conn.data_to_send())
                return writer.drain()
            def is_closing(self):
                return self.closed
            def close(self):
                self.closed = True
                write_wait.set()
            def window_update(self):
                write_full.set()
            def send_headers(self, headers):
                conn.send_headers(stream_id, headers)
                writer.write(conn.data_to_send())
        stream_writer = StreamWriter()
        async def write_job():
            while not stream_writer.closed:
                while len(write_buffer) > 0:
                    while conn.local_flow_control_window(stream_id) <= 0:
                        write_full.clear()
                        await write_full.wait()
                        if stream_writer.closed:
                            break
                    chunk_size = min(conn.local_flow_control_window(stream_id), len(write_buffer), conn.max_outbound_frame_size)
                    conn.send_data(stream_id, write_buffer[:chunk_size])
                    writer.write(conn.data_to_send())
                    del write_buffer[:chunk_size]
                if not stream_writer.closed:
                    write_wait.clear()
                    await write_wait.wait()
            conn.send_data(stream_id, b'', end_stream=True)
            writer.write(conn.data_to_send())
        asyncio.ensure_future(write_job())
        return reader, stream_writer
    async def wait_h2_connection(self, local_addr, family):
        if self.handshake is not None:
            if not self.handshake.done():
                await self.handshake
        else:
            self.handshake = asyncio.get_event_loop().create_future()
            reader, writer = await super().wait_open_connection(None, None, local_addr, family)
            asyncio.ensure_future(self.handler(reader, writer))
            await self.handshake
        return self.handshake.result()
    async def wait_open_connection(self, host, port, local_addr, family):
        conn, streams, writer = await self.wait_h2_connection(local_addr, family)
        stream_id = conn.get_next_available_stream_id()
        conn._begin_new_stream(stream_id, stream_id%2)
        stream_reader, stream_writer = self.get_stream(conn, writer, stream_id)
        streams[stream_id] = (stream_reader, stream_writer)
        return stream_reader, stream_writer
    def start_server(self, args, stream_handler=stream_handler):
        handler = functools.partial(stream_handler, **vars(self), **args)
        return super().start_server(args, functools.partial(self.handler, client_side=False, stream_handler=handler))

class ProxyQUIC(ProxySimple):
    def __init__(self, quicserver, quicclient, **kw):
        super().__init__(**kw)
        self.quicserver = quicserver
        self.quicclient = quicclient
        self.handshake = None
    def patch_writer(self, writer):
        async def drain():
            writer._transport.protocol.transmit()
        #print('stream_id', writer.get_extra_info("stream_id"))
        remote_addr = writer._transport.protocol._quic._network_paths[0].addr
        writer.get_extra_info = dict(peername=remote_addr, sockname=remote_addr).get
        writer.drain = drain
        closed = False
        writer.is_closing = lambda: closed
        def close():
            nonlocal closed
            closed = True
            try:
                writer.write_eof()
            except Exception:
                pass
        writer.close = close
    async def wait_quic_connection(self):
        if self.handshake is not None:
            if not self.handshake.done():
                await self.handshake
        else:
            self.handshake = asyncio.get_event_loop().create_future()
            import aioquic.asyncio, aioquic.quic.events
            class Protocol(aioquic.asyncio.QuicConnectionProtocol):
                def quic_event_received(s, event):
                    if isinstance(event, aioquic.quic.events.HandshakeCompleted):
                        self.handshake.set_result(s)
                    elif isinstance(event, aioquic.quic.events.ConnectionTerminated):
                        self.handshake = None
                        self.quic_egress_acm = None
                    elif isinstance(event, aioquic.quic.events.StreamDataReceived):
                        if event.stream_id in self.udpmap:
                            self.udpmap[event.stream_id](self.udp_packet_unpack(event.data))
                            return
                    super().quic_event_received(event)
            self.quic_egress_acm = aioquic.asyncio.connect(self.host_name, self.port, create_protocol=Protocol, configuration=self.quicclient)
            conn = await self.quic_egress_acm.__aenter__()
            await self.handshake
    async def udp_open_connection(self, host, port, data, addr, reply):
        await self.wait_quic_connection()
        conn = self.handshake.result()
        if addr in self.udpmap:
            stream_id = self.udpmap[addr]
        else:
            stream_id = conn._quic.get_next_available_stream_id(False)
            self.udpmap[addr] = stream_id
            self.udpmap[stream_id] = reply
            conn._quic._get_or_create_stream_for_send(stream_id)
        conn._quic.send_stream_data(stream_id, data, False)
        conn.transmit()
    async def wait_open_connection(self, *args):
        await self.wait_quic_connection()
        conn = self.handshake.result()
        stream_id = conn._quic.get_next_available_stream_id(False)
        conn._quic._get_or_create_stream_for_send(stream_id)
        reader, writer = conn._create_stream(stream_id)
        self.patch_writer(writer)
        return reader, writer
    async def udp_start_server(self, args):
        import aioquic.asyncio, aioquic.quic.events
        class Protocol(aioquic.asyncio.QuicConnectionProtocol):
            def quic_event_received(s, event):
                if isinstance(event, aioquic.quic.events.StreamDataReceived):
                    stream_id = event.stream_id
                    addr = ('quic '+self.bind, stream_id)
                    event.sendto = lambda data, addr: (s._quic.send_stream_data(stream_id, data, False), s.transmit())
                    event.get_extra_info = {}.get
                    asyncio.ensure_future(datagram_handler(event, event.data, addr, **vars(self), **args))
                    return
                super().quic_event_received(event)
        return await aioquic.asyncio.serve(self.host_name, self.port, configuration=self.quicserver, create_protocol=Protocol), None
    def start_server(self, args, stream_handler=stream_handler):
        import aioquic.asyncio
        def handler(reader, writer):
            self.patch_writer(writer)
            asyncio.ensure_future(stream_handler(reader, writer, **vars(self), **args))
        return aioquic.asyncio.serve(self.host_name, self.port, configuration=self.quicserver, stream_handler=handler)

class ProxyH3(ProxyQUIC):
    def get_stream(self, conn, stream_id):
        remote_addr = conn._quic._network_paths[0].addr
        reader = asyncio.StreamReader()
        class StreamWriter():
            def __init__(self):
                self.closed = False
                self.headers = asyncio.get_event_loop().create_future()
            def get_extra_info(self, key):
                return dict(peername=remote_addr, sockname=remote_addr).get(key)
            def write(self, data):
                conn.http.send_data(stream_id, data, False)
                conn.transmit()
            async def drain(self):
                conn.transmit()
            def is_closing(self):
                return self.closed
            def close(self):
                if not self.closed:
                    conn.http.send_data(stream_id, b'', True)
                    conn.transmit()
                    conn.close_stream(stream_id)
                self.closed = True
            def send_headers(self, headers):
                conn.http.send_headers(stream_id, [(i.encode(), j.encode()) for i, j in headers])
                conn.transmit()
        return reader, StreamWriter()
    def get_protocol(self, server_side=False, handler=None):
        import aioquic.asyncio, aioquic.quic.events, aioquic.h3.connection, aioquic.h3.events
        class Protocol(aioquic.asyncio.QuicConnectionProtocol):
            def __init__(s, *args, **kw):
                super().__init__(*args, **kw)
                s.http = aioquic.h3.connection.H3Connection(s._quic)
                s.streams = {}
            def quic_event_received(s, event):
                if not server_side:
                    if isinstance(event, aioquic.quic.events.HandshakeCompleted):
                        self.handshake.set_result(s)
                    elif isinstance(event, aioquic.quic.events.ConnectionTerminated):
                        self.handshake = None
                        self.quic_egress_acm = None
                if s.http is not None:
                    for http_event in s.http.handle_event(event):
                        s.http_event_received(http_event)
            def http_event_received(s, event):
                if isinstance(event, aioquic.h3.events.HeadersReceived):
                    if event.stream_id not in s.streams and server_side:
                        reader, writer = s.create_stream(event.stream_id)
                        writer.headers.set_result(event.headers)
                        asyncio.ensure_future(handler(reader, writer))
                elif isinstance(event, aioquic.h3.events.DataReceived) and event.stream_id in s.streams:
                    reader, writer = s.streams[event.stream_id]
                    if event.data:
                        reader.feed_data(event.data)
                    if event.stream_ended:
                        reader.feed_eof()
                    s.close_stream(event.stream_id)
            def create_stream(s, stream_id=None):
                if stream_id is None:
                    stream_id = s._quic.get_next_available_stream_id(False)
                    s._quic._get_or_create_stream_for_send(stream_id)
                reader, writer = self.get_stream(s, stream_id)
                s.streams[stream_id] = (reader, writer)
                return reader, writer
            def close_stream(s, stream_id):
                if stream_id in s.streams:
                    reader, writer = s.streams[stream_id]
                    if reader.at_eof() and writer.is_closing():
                        s.streams.pop(stream_id)
        return Protocol
    async def wait_h3_connection(self):
        if self.handshake is not None:
            if not self.handshake.done():
                await self.handshake
        else:
            import aioquic.asyncio
            self.handshake = asyncio.get_event_loop().create_future()
            self.quic_egress_acm = aioquic.asyncio.connect(self.host_name, self.port, create_protocol=self.get_protocol(), configuration=self.quicclient)
            conn = await self.quic_egress_acm.__aenter__()
            await self.handshake
    async def wait_open_connection(self, *args):
        await self.wait_h3_connection()
        return self.handshake.result().create_stream()
    def start_server(self, args, stream_handler=stream_handler):
        import aioquic.asyncio
        return aioquic.asyncio.serve(self.host_name, self.port, configuration=self.quicserver, create_protocol=self.get_protocol(True, functools.partial(stream_handler, **vars(self), **args)))

class ProxySSH(ProxySimple):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.sshconn = None
    def logtext(self, host, port):
        return f' -> sshtunnel {self.bind}' + self.jump.logtext(host, port)
    def patch_stream(self, ssh_reader, writer, host, port):
        reader = asyncio.StreamReader()
        async def channel():
            while not ssh_reader.at_eof() and not writer.is_closing():
                buf = await ssh_reader.read(65536)
                if not buf:
                    break
                reader.feed_data(buf)
            reader.feed_eof()
        asyncio.ensure_future(channel())
        remote_addr = ('ssh:'+str(host), port)
        writer.get_extra_info = dict(peername=remote_addr, sockname=remote_addr).get
        return reader, writer
    async def wait_ssh_connection(self, local_addr=None, family=0, tunnel=None):
        if self.sshconn is not None and not self.sshconn.cancelled():
            if not self.sshconn.done():
                await self.sshconn
        else:
            self.sshconn = asyncio.get_event_loop().create_future()
            try:
                import asyncssh
            except Exception:
                raise Exception('Missing library: "pip3 install asyncssh"')
            username, password = self.auth.decode().split(':', 1)
            if password.startswith(':'):
                client_keys = [password[1:]]
                password = None
            else:
                client_keys = None
            conn = await asyncssh.connect(host=self.host_name, port=self.port, local_addr=local_addr, family=family, x509_trusted_certs=None, known_hosts=None, username=username, password=password, client_keys=client_keys, keepalive_interval=60, tunnel=tunnel)
            self.sshconn.set_result(conn)
    async def wait_open_connection(self, host, port, local_addr, family, tunnel=None):
        try:
            await self.wait_ssh_connection(local_addr, family, tunnel)
            conn = self.sshconn.result()
            if isinstance(self.jump, ProxySSH):
                reader, writer = await self.jump.wait_open_connection(host, port, None, None, conn)
            else:
                host, port = self.jump.destination(host, port)
                if self.jump.unix:
                    reader, writer = await conn.open_unix_connection(self.jump.bind)
                else:
                    reader, writer = await conn.open_connection(host, port)
                reader, writer = self.patch_stream(reader, writer, host, port)
            return reader, writer
        except Exception as ex:
            if not self.sshconn.done():
                self.sshconn.set_exception(ex)
            self.sshconn = None
            raise
    async def start_server(self, args, stream_handler=stream_handler, tunnel=None):
        if type(self.jump) is ProxyDirect:
            raise Exception('ssh server mode unsupported')
        await self.wait_ssh_connection(tunnel=tunnel)
        conn = self.sshconn.result()
        if isinstance(self.jump, ProxySSH):
            return await self.jump.start_server(args, stream_handler, conn)
        else:
            def handler(host, port):
                def handler_stream(reader, writer):
                    reader, writer = self.patch_stream(reader, writer, host, port)
                    return stream_handler(reader, writer, **vars(self.jump), **args)
                return handler_stream
            if self.jump.unix:
                return await conn.start_unix_server(handler, self.jump.bind)
            else:
                return await conn.start_server(handler, self.jump.host_name, self.jump.port)

class ProxyBackward(ProxySimple):
    def __init__(self, backward, backward_num, **kw):
        super().__init__(**kw)
        self.backward = backward
        self.server = backward
        while type(self.server.jump) != ProxyDirect:
            self.server = self.server.jump
        self.backward_num = backward_num
        self.closed = False
        self.writers = set()
        self.conn = asyncio.Queue()
    async def wait_open_connection(self, *args):
        while True:
            reader, writer = await self.conn.get()
            if not reader.at_eof() and not writer.is_closing():
                return reader, writer
    def close(self):
        self.closed = True
        for writer in self.writers:
            try:
                self.writer.close()
            except Exception:
                pass
    async def start_server(self, args, stream_handler=stream_handler):
        handler = functools.partial(stream_handler, **vars(self.server), **args)
        for _ in range(self.backward_num):
            asyncio.ensure_future(self.start_server_run(handler))
        return self
    async def start_server_run(self, handler):
        errwait = 0
        while not self.closed:
            wait = self.backward.open_connection(self.host_name, self.port, self.lbind, None)
            try:
                reader, writer = await asyncio.wait_for(wait, timeout=SOCKET_TIMEOUT)
                if self.closed:
                    writer.close()
                    break
                if isinstance(self.server, ProxyQUIC):
                    writer.write(b'\x01')
                writer.write(self.server.auth)
                self.writers.add(writer)
                try:
                    data = await reader.read_n(1)
                except asyncio.TimeoutError:
                    data = None
                if data and data[0] != 0:
                    reader.rollback(data)
                    asyncio.ensure_future(handler(reader, writer))
                else:
                    writer.close()
                errwait = 0
                self.writers.discard(writer)
                writer = None
            except Exception as ex:
                try:
                    writer.close()
                except Exception:
                    pass
                if not self.closed:
                    await asyncio.sleep(errwait)
                    errwait = min(errwait*1.3 + 0.1, 30)
    def start_backward_client(self, args):
        async def handler(reader, writer, **kw):
            auth = self.server.auth
            if isinstance(self.server, ProxyQUIC):
                auth = b'\x01'+auth
            if auth:
                try:
                    assert auth == (await reader.read_n(len(auth)))
                except Exception:
                    return
            await self.conn.put((reader, writer))
        return self.backward.start_server(args, handler)


def compile_rule(filename):
    if filename.startswith("{") and filename.endswith("}"):
        return re.compile(filename[1:-1]).match
    with open(filename) as f:
        return re.compile('(:?'+''.join('|'.join(i.strip() for i in f if i.strip() and not i.startswith('#')))+')$').match

def proxies_by_uri(uri_jumps):
    jump = DIRECT
    for uri in reversed(uri_jumps.split('__')):
        jump = proxy_by_uri(uri, jump)
    return jump

sslcontexts = []

def proxy_by_uri(uri, jump):
    scheme, _, uri = uri.partition('://')
    url = urllib.parse.urlparse('s://'+uri)
    rawprotos = [i.lower() for i in scheme.split('+')]
    err_str, protos = proto.get_protos(rawprotos)
    protonames = [i.name for i in protos]
    if err_str:
        raise argparse.ArgumentTypeError(err_str)
    if 'ssl' in rawprotos or 'secure' in rawprotos:
        import ssl
        sslserver = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        sslclient = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        if 'ssl' in rawprotos:
            sslclient.check_hostname = False
            sslclient.verify_mode = ssl.CERT_NONE
        sslcontexts.append(sslserver)
        sslcontexts.append(sslclient)
    else:
        sslserver = sslclient = None
    if 'quic' in rawprotos or 'h3' in protonames:
        try:
            import ssl, aioquic.quic.configuration
        except Exception:
            raise Exception('Missing library: "pip3 install aioquic"')
        quicserver = aioquic.quic.configuration.QuicConfiguration(is_client=False, max_stream_data=2**60, max_data=2**60, idle_timeout=SOCKET_TIMEOUT)
        quicclient = aioquic.quic.configuration.QuicConfiguration(max_stream_data=2**60, max_data=2**60, idle_timeout=SOCKET_TIMEOUT*5)
        quicclient.verify_mode = ssl.CERT_NONE
        sslcontexts.append(quicserver)
        sslcontexts.append(quicclient)
    if 'h2' in rawprotos:
        try:
            import h2
        except Exception:
            raise Exception('Missing library: "pip3 install h2"')
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
    if loc:
        host_name, port = proto.netloc_split(loc, default_port=22 if 'ssh' in rawprotos else 8080)
    else:
        host_name = port = None
    if url.fragment.startswith('#'):
        with open(url.fragment[1:]) as f:
            auth = f.read().rstrip().encode()
    else:
        auth = url.fragment.encode()
    users = [i.rstrip() for i in auth.split(b'\n')] if auth else None
    if 'direct' in protonames:
        return ProxyDirect(lbind=lbind)
    else:
        params = dict(jump=jump, protos=protos, cipher=cipher, users=users, rule=url.query, bind=loc or urlpath,
                      host_name=host_name, port=port, unix=not loc, lbind=lbind, sslclient=sslclient, sslserver=sslserver)
        if 'quic' in rawprotos:
            proxy = ProxyQUIC(quicserver, quicclient, **params)
        elif 'h3' in protonames:
            proxy = ProxyH3(quicserver, quicclient, **params)
        elif 'h2' in protonames:
            proxy = ProxyH2(**params)
        elif 'ssh' in protonames:
            proxy = ProxySSH(**params)
        else:
            proxy = ProxySimple(**params)
        if 'in' in rawprotos:
            proxy = ProxyBackward(proxy, rawprotos.count('in'), **params)
        return proxy

async def test_url(url, rserver):
    url = urllib.parse.urlparse(url)
    assert url.scheme in ('http', 'https'), f'Unknown scheme {url.scheme}'
    host_name, port = proto.netloc_split(url.netloc, default_port = 80 if url.scheme=='http' else 443)
    initbuf = f'GET {url.path or "/"} HTTP/1.1\r\nHost: {host_name}\r\nUser-Agent: pproxy-{__version__}\r\nAccept: */*\r\nConnection: close\r\n\r\n'.encode()
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
        if url.scheme == 'https':
            import ssl
            sslclient = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            sslclient.check_hostname = False
            sslclient.verify_mode = ssl.CERT_NONE
            reader, writer = proto.sslwrap(reader, writer, sslclient, False, host_name)
        writer.write(initbuf)
        headers = await reader.read_until(b'\r\n\r\n')
        print(headers.decode()[:-4])
        print(f'--------------------------------')
        body = bytearray()
        while not reader.at_eof():
            s = await reader.read(65536)
            if not s:
                break
            body.extend(s)
        print(body.decode('utf8', 'ignore'))
    print(f'============ success ============')

def print_server_started(option, server, print_fn):
    for s in server.sockets:
        # https://github.com/MagicStack/uvloop/blob/master/uvloop/pseudosock.pyx
        laddr = s.getsockname() # tuple size varies with protocol family
        h = laddr[0]
        p = laddr[1]
        f = str(s.family)
        ipversion = "ipv4" if f == "AddressFamily.AF_INET" else ("ipv6" if f == "AddressFamily.AF_INET6" else "ipv?") # TODO better
        bind = ipversion+' '+h+':'+str(p)
        print_fn(option, bind)

def main(args = None):
    origin_argv = sys.argv[1:] if args is None else args

    parser = argparse.ArgumentParser(description=__description__+'\nSupported protocols: http,socks4,socks5,shadowsocks,shadowsocksr,redirect,pf,tunnel', epilog=f'Online help: <{__url__}>')
    parser.add_argument('-l', dest='listen', default=[], action='append', type=proxies_by_uri, help='tcp server uri (default: http+socks4+socks5://:8080/)')
    parser.add_argument('-r', dest='rserver', default=[], action='append', type=proxies_by_uri, help='tcp remote server uri (default: direct)')
    parser.add_argument('-ul', dest='ulisten', default=[], action='append', type=proxies_by_uri, help='udp server setting uri (default: none)')
    parser.add_argument('-ur', dest='urserver', default=[], action='append', type=proxies_by_uri, help='udp remote server uri (default: direct)')
    parser.add_argument('-b', dest='block', type=compile_rule, help='block regex rules')
    parser.add_argument('-a', dest='alived', default=0, type=int, help='interval to check remote alive (default: no check)')
    parser.add_argument('-s', dest='salgorithm', default='fa', choices=('fa', 'rr', 'rc', 'lc'), help='scheduling algorithm (default: first_available)')
    parser.add_argument('-d', dest='debug', action='count', help='turn on debug to see tracebacks (default: no debug)')
    parser.add_argument('-v', dest='v', action='count', help='print verbose output')
    parser.add_argument('--ssl', dest='sslfile', help='certfile[,keyfile] if server listen in ssl mode')
    parser.add_argument('--pac', help='http PAC path')
    parser.add_argument('--get', dest='gets', default=[], action='append', help='http custom {path,file}')
    parser.add_argument('--auth', dest='authtime', type=int, default=86400*30, help='re-auth time interval for same ip (default: 86400*30)')
    parser.add_argument('--sys', action='store_true', help='change system proxy setting (mac, windows)')
    parser.add_argument('--reuse', dest='ruport', action='store_true', help='set SO_REUSEPORT (Linux only)')
    parser.add_argument('--daemon', dest='daemon', action='store_true', help='run as a daemon (Linux only)')
    parser.add_argument('--test', help='test this url for all remote proxies and exit')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    args = parser.parse_args(args)
    if args.sslfile:
        sslfile = args.sslfile.split(',')
        for context in sslcontexts:
            context.load_cert_chain(*sslfile)
    elif any(map(lambda o: o.sslclient or isinstance(o, ProxyQUIC), args.listen+args.ulisten)):
        print('You must specify --ssl to listen in ssl mode')
        return
    if args.test:
        asyncio.get_event_loop().run_until_complete(test_url(args.test, args.rserver))
        return
    if not args.listen and not args.ulisten:
        args.listen.append(proxies_by_uri('http+socks4+socks5://:8080/'))
    args.httpget = {}
    if args.pac:
        pactext = 'function FindProxyForURL(u,h){' + (f'var b=/^(:?{args.block.__self__.pattern})$/i;if(b.test(h))return "";' if args.block else '')
        for i, option in enumerate(args.rserver):
            pactext += (f'var m{i}=/^(:?{option.rule.__self__.pattern})$/i;if(m{i}.test(h))' if option.rule else '') + 'return "PROXY %(host)s";'
        args.httpget[args.pac] = pactext+'return "DIRECT";}'
        args.httpget[args.pac+'/all'] = 'function FindProxyForURL(u,h){return "PROXY %(host)s";}'
        args.httpget[args.pac+'/none'] = 'function FindProxyForURL(u,h){return "DIRECT";}'
    for gets in args.gets:
        path, filename = gets.split(',', 1)
        with open(filename, 'rb') as f:
            args.httpget[path] = f.read()
    if args.daemon:
        try:
            __import__('daemon').DaemonContext().open()
        except ModuleNotFoundError:
            print("Missing library: pip3 install python-daemon")
            return
    # Try to use uvloop instead of the default event loop
    try:
        __import__('uvloop').install()
        print('Using uvloop')
    except ModuleNotFoundError:
        pass
    loop = asyncio.get_event_loop()
    if args.v:
        from . import verbose
        verbose.setup(loop, args)
    servers = []
    admin.config.update({'argv': origin_argv, 'servers': servers, 'args': args, 'loop': loop})
    def print_fn(option, bind=None):
        print('Serving on', (bind or option.bind), 'by', ",".join(i.name for i in option.protos) + ('(SSL)' if option.sslclient else ''), '({}{})'.format(option.cipher.name, ' '+','.join(i.name() for i in option.cipher.plugins) if option.cipher and option.cipher.plugins else '') if option.cipher else '')
    for option in args.listen:
        try:
            server = loop.run_until_complete(option.start_server(vars(args)))
            print_server_started(option, server, print_fn)
            servers.append(server)
        except Exception as ex:
            print_fn(option)
            print('Start server failed.\n\t==>', ex)
    def print_fn(option, bind=None):
        print('Serving on UDP', (bind or option.bind), 'by', ",".join(i.name for i in option.protos), f'({option.cipher.name})' if option.cipher else '')
    for option in args.ulisten:
        try:
            server, protocol = loop.run_until_complete(option.udp_start_server(vars(args)))
            print_server_started(option, server, print_fn)
            servers.append(server)
        except Exception as ex:
            print_fn(option)
            print('Start server failed.\n\t==>', ex)
    def print_fn(option, bind=None):
        print('Serving on', (bind or option.bind), 'backward by', ",".join(i.name for i in option.protos) + ('(SSL)' if option.sslclient else ''), '({}{})'.format(option.cipher.name, ' '+','.join(i.name() for i in option.cipher.plugins) if option.cipher and option.cipher.plugins else '') if option.cipher else '')
    for option in args.rserver:
        if isinstance(option, ProxyBackward):
            try:
                server = loop.run_until_complete(option.start_backward_client(vars(args)))
                print_server_started(option, server, print_fn)
                servers.append(server)
            except Exception as ex:
                print_fn(option)
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
    for task in asyncio.all_tasks(loop) if hasattr(asyncio, 'all_tasks') else asyncio.Task.all_tasks():
        task.cancel()
    for server in servers:
        server.close()
    for server in servers:
        if hasattr(server, 'wait_closed'):
            loop.run_until_complete(server.wait_closed())
    loop.run_until_complete(loop.shutdown_asyncgens())
    if admin.config.get('reload', False):
        admin.config['reload'] = False
        main(admin.config['argv'])
    loop.close()

if __name__ == '__main__':
    main()
