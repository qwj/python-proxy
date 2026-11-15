import asyncio
import unittest

import pproxy


class BackwardConnectionTest(unittest.TestCase):
    def test_discarded_connections_are_closed(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(asyncio.wait_for(self.check_discarded_connections(), 10))
        finally:
            loop.close()
            asyncio.set_event_loop(None)

    async def check_discarded_connections(self):
        proxy = pproxy.Connection('http+in://127.0.0.1:0')
        server = await proxy.start_backward_client({})
        port = server.sockets[0].getsockname()[1]
        writers = []
        try:
            stale = []
            queued = []
            for _ in range(3):
                peer_reader, peer_writer = await asyncio.open_connection('127.0.0.1', port)
                writers.append(peer_writer)
                reader, writer = await asyncio.wait_for(proxy.conn.get(), 2)
                writers.append(writer)
                peer_writer.write_eof()
                self.assertEqual(await asyncio.wait_for(reader.read(1), 2), b'')
                queued.append((reader, writer))
                stale.append(peer_reader)
            for connection in queued:
                await proxy.conn.put(connection)

            peer_reader, peer_writer = await asyncio.open_connection('127.0.0.1', port)
            writers.append(peer_writer)
            reader, writer = await proxy.open_connection(None, None, None, None, timeout=2)
            writers.append(writer)
            for peer in stale:
                self.assertEqual(await asyncio.wait_for(peer.read(1), 2), b'')

            # Discarding stale streams must preserve the next usable connection.
            writer.write(b'request')
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(peer_reader.readexactly(7), 2), b'request')
            peer_writer.write(b'response')
            await peer_writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(8), 2), b'response')
        finally:
            server.close()
            for writer in writers:
                writer.close()
            await server.wait_closed()
            await asyncio.sleep(0)

    def test_buffered_half_closed_connection_is_preserved(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(asyncio.wait_for(self.check_buffered_connection(), 10))
        finally:
            loop.close()
            asyncio.set_event_loop(None)

    async def check_buffered_connection(self):
        proxy = pproxy.Connection('http+in://127.0.0.1:0')
        server = await proxy.start_backward_client({})
        writers = []
        try:
            port = server.sockets[0].getsockname()[1]
            peer_reader, peer_writer = await asyncio.open_connection('127.0.0.1', port)
            writers.append(peer_writer)
            peer_writer.write(b'buffered request')
            await peer_writer.drain()
            peer_writer.write_eof()
            reader, writer = await proxy.open_connection(None, None, None, None, timeout=2)
            writers.append(writer)
            self.assertEqual(await asyncio.wait_for(reader.readexactly(16), 2), b'buffered request')
            self.assertEqual(await asyncio.wait_for(reader.read(1), 2), b'')
            writer.write(b'response')
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(peer_reader.readexactly(8), 2), b'response')
        finally:
            server.close()
            for writer in writers:
                writer.close()
            await server.wait_closed()
            await asyncio.sleep(0)
