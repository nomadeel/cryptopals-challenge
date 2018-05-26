#!/usr/bin/env python2

import web
import sha1
import time
import sys
import os

key = "hi"
sleep_duration = 0.005

urls = (
    '/test', 'hmac'
)
app = web.application(urls, globals())


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
        file_mac = sha1.Sha1Hash().update(key + file_name).digest()    
        for i in range(0, len(file_mac)):
            if mac[i] != file_mac[i]:
                return False
            time.sleep(sleep_duration)
        return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: {} <port>".format(sys.argv[0]))
        sys.exit()

    print(sha1.Sha1Hash().update("hi" + "file").hexdigest())
    app.run()
