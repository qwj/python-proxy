import asyncio
import pproxy

async def test_tcp():
    conn = pproxy.Connection('ss://chacha20:123@127.0.0.1:12345')
    reader, writer = await conn.tcp_connect('google.com', 80)
    writer.write(b'GET / HTTP/1.1\r\n\r\n')
    data = await reader.read(1024*16)
    print(data.decode())

async def test_udp():
    conn = pproxy.Connection('ss://chacha20:123@127.0.0.1:12345')
    answer = asyncio.Future()
    await conn.udp_sendto('8.8.8.8', 53, b'hello', answer.set_result)
    await answer
    print(answer.result())

asyncio.run(test_tcp())
asyncio.run(test_udp())
