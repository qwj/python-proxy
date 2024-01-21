import json
import asyncio
config = {}


async def reply_http(reply, ver, code, content):
    await reply(code, f'{ver} {code}\r\nConnection: close\r\nContent-Type: text/plain\r\nCache-Control: max-age=900\r\nContent-Length: {len(content)}\r\n\r\n'.encode(), content, True)


async def status_handler(reply, **kwarg):
    method = kwarg.get('method')
    if method == 'GET':
        data = {"status": "ok"}
        value = json.dumps(data).encode()
        ver = kwarg.get('ver')
        await reply_http(reply, ver, '200 OK', value)


async def configs_handler(reply, **kwarg):
    method = kwarg.get('method')
    ver = kwarg.get('ver')

    if method == 'GET':
        data = {"argv": config['argv']}
        value = json.dumps(data).encode()
        await reply_http(reply, ver, '200 OK', value)
    elif method == 'POST':
        config['argv'] = kwarg.get('content').decode().split(' ')
        config['reload'] = True
        data = {"result": 'ok'}
        value = json.dumps(data).encode()
        await reply_http(reply, ver, '200 OK', value)
        raise KeyboardInterrupt


httpget = {
    '/status': status_handler,
    '/configs': configs_handler,
}
