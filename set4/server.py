#!/usr/bin/env python2

import web
import sha1
import time
import sys
import os

key = os.urandom(16)
sleep_duration = 0.05

urls = (
    '/test', 'hmac'
)
app = web.application(urls, globals())

def insecure_compare(file_name, mac):
    file_mac = sha1.Sha1Hash().update(key + file_name).digest()    
    for i in range(0, len(file_mac)):
        if mac[i] != file_mac[i]:
            return False
        time.sleep(sleep_duration)
    return True

class hmac:
    def GET(self):
        args = web.input()
        # convert the signature into byte string
        provided_string = args["signature"].decode("hex")
        if insecure_compare(args["file"], provided_string) is True:
            raise web.OK()
        else:
            return web.internalerror()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: {} <sleep duration: 50ms or 5ms>".format(sys.argv[0]))
        sys.exit()

    if not (sys.argv[1] != 5 and sys.argv[1] != 50):
        print("hi")
        print("Usage: {} <sleep duration: 50ms or 5ms>".format(sys.argv[0]))
        sys.exit()

    app.run()
