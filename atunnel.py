#!/usr/bin/env python

import argparse
import asyncio
from hashlib import md5

from Crypto.Cipher import AES


class Tunnel():
    def __init__(self, secret, client_mode, backend, loop):
        super(Tunnel, self).__init__()
        self.secret = md5(secret.encode('utf-8')).hexdigest()
        self.client_mode = client_mode
        self.backend_host = backend.split(':')[0]
        self.backend_port = int(backend.split(':')[1])
        self.loop = loop

    @asyncio.coroutine
    def start(self, host, port):
        coro = yield from asyncio.start_server(
            self.handle, host, port, loop=self.loop)
        return coro

    @asyncio.coroutine
    def handle(self, reader, writer):
        try:
            backend_reader, backend_writer = \
                yield from asyncio.open_connection(
                    self.backend_host,
                    self.backend_port,
                    loop=self.loop
                )
        except ConnectionError:
            writer.close()
            return

        crypto = AES.new(self.secret, AES.MODE_CFB, self.secret[:16])

        if self.client_mode:
            yield from asyncio.wait([
                self.pipe(reader, backend_writer, crypto.encrypt),
                self.pipe(backend_reader, writer, crypto.decrypt),
            ])
        else:
            yield from asyncio.wait([
                self.pipe(reader, backend_writer, crypto.decrypt),
                self.pipe(backend_reader, writer, crypto.encrypt),
            ])

    @asyncio.coroutine
    def pipe(self, reader, writer, processer):
        while True:
            try:
                data = yield from reader.read(4096)
            except ConnectionError:
                break

            if not data:
                break
            writer.write(processer(data))
            try:
                yield from writer.drain()
            except ConnectionError:
                break

        writer.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Tunnel.')
    parser.add_argument('--secret', default='', type=str,
                        help='password used to encrypt the data')
    parser.add_argument('--client-mode', default=1, type=int,
                        help='if running at client mode')
    parser.add_argument('--listen', default=':9001', type=str,
                        help='host:port ttunnel listen on')
    parser.add_argument('--backend', default='127.0.0.1:6400', type=str,
                        help='host:port of the backend')
    args = parser.parse_args()

    event_loop = asyncio.get_event_loop()
    tunnel = Tunnel(args.secret, args.client_mode, args.backend, event_loop)
    coro = tunnel.start(args.listen.split(':')[0],
                        int(args.listen.split(':')[1]))
    server = event_loop.run_until_complete(coro)

    print('Serving on {}.'.format(server.sockets[0].getsockname()))
    try:
        event_loop.run_forever()
    except KeyboardInterrupt:
        pass

    server.close()
    event_loop.run_until_complete(server.wait_closed())
    event_loop.close()
