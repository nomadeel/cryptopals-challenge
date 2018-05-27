#!/usr/bin/env python2

import web
import sha1
import time
import sys
import os

key = "hi"
sleep_duration = 0.005
block_size = 64

urls = (
    '/test', 'hmac'
)
app = web.application(urls, globals())

def calculate_hmac(file_name, key):
    if len(key) > block_size:
        key = sha1.Sha1Hash().update(key).digest()
    elif len(key) < block_size:
        key += '\x00' * (block_size - len(key))

    key = bytearray(key)

    o_key_pad = bytearray(len(key))
    i_key_pad = bytearray(len(key))

    for i in key:
        o_key_pad += bytearray([i ^ 0x5c])
        i_key_pad += bytearray([i ^ 0x36])

    i_key_hash = sha1.Sha1Hash().update(i_key_pad + file_name).digest()
    return sha1.Sha1Hash().update(o_key_pad + i_key_hash).digest()

class hmac:
    def POST(self):
        args = web.input()
        # convert the signature into byte string
        file_name = args["file"].encode("ascii")
        provided_string = args["signature"].decode("hex")
        if self.insecure_compare(file_name, provided_string) is True:
            raise web.OK()
        else:
            raise web.internalerror("bad mac")

    def insecure_compare(self, file_name, mac):
        file_mac = calculate_hmac(file_name, key)
        for i in range(0, len(file_mac)):
            if mac[i] != file_mac[i]:
                return False
            time.sleep(sleep_duration)
        return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: {} <port>".format(sys.argv[0]))
        sys.exit()

    print(calculate_hmac("file", key).encode("hex"))
    app.run()
