import asyncio
import io
import os
import socket
import struct

import pytest


class AioConnection:
    """
    Connection class based on an arbitrary file descriptor (Unix only), or
    a socket handle (Windows).
    """
    def __init__(self, handle):
        self._handle = handle

    async def _send(self, data):
        remaining = len(data)
        while True:
            n = os.write(self._handle, data)
            remaining -= n
            if remaining == 0:
                break
            data = data[n:]
            await asyncio.sleep(0)

    async def _recv(self, size):
        buf = io.BytesIO()
        remaining = size
        while remaining > 0:
            chunk = os.read(self._handle, remaining)
            n = len(chunk)
            if n == 0:
                if remaining == size:
                    raise EOFError
                else:
                    raise OSError("got end of file during message")
            buf.write(chunk)
            remaining -= n
            await asyncio.sleep(0)
        return buf

    async def send_bytes(self, data):
        header = struct.pack("!i", len(data))
        await self._send(header)
        return await self._send(data)

    async def recv_bytes(self, maxlength=None):
        size_buf = await self._recv(4)
        size, = struct.unpack("!i", size_buf.getvalue())
        value_buf = await self._recv(size)
        return value_buf.getvalue()


async def Pipe():
    '''
    Returns pair of connection objects at either end of a pipe
    '''
    s1, s2 = socket.socketpair()
    s1.setblocking(True)
    s2.setblocking(True)
    print('setup socket pair')
    c1 = AioConnection(s1.detach())
    c2 = AioConnection(s2.detach())
    print('setup connections')

    return c1, c2


@pytest.mark.asyncio
async def test_aio_connection_pipe(event_loop):
    left, right = await Pipe()

    await left.send_bytes(b'test-send')
    result = await right.recv_bytes()
    assert result == b'test-send'
