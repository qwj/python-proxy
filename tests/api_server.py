import asyncio
import pproxy

server = pproxy.Server('ss://0.0.0.0:1234')
remote = pproxy.Connection('ss://1.2.3.4:5678')
args = dict( rserver = [remote],
             verbose = print )

loop = asyncio.get_event_loop()
handler = loop.run_until_complete(server.start_server(args))
try:
    loop.run_forever()
except KeyboardInterrupt:
    print('exit!')

handler.close()
loop.run_until_complete(handler.wait_closed())
loop.run_until_complete(loop.shutdown_asyncgens())
loop.close()
