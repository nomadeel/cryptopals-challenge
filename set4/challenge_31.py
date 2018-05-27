#!/usr/bin/env python2

import sha1
import urllib
import urllib2
import time
import struct

server_url="http://0.0.0.0:8080/test"

sha1hash_length = 20
epsilon = 5
test_server = True
block_size = 64

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

# Test the server

def test():
    key = "hi"
    success_mac = calculate_hmac("file", key).encode("hex")
    success_args = { "file": "file", "signature": success_mac }
    url_data = urllib.urlencode(success_args)

    response = urllib2.urlopen(urllib2.Request(server_url, url_data))
    assert response.code == 200

    failure_mac = 'ffffffffffffffffffffffffffffffffffffffff'
    failure_args = { "file": "file", "signature": failure_mac }
    url_data = urllib.urlencode(failure_args)

    try:
        response = urllib2.urlopen(urllib2.Request(server_url, url_data))
    except urllib2.URLError, e:
        assert e.code == 500

def crack_hmac(file_name):
    known_bytes = ""
    num_uncovered = 0
    max_time = 0
    character = ""
    for i in range(0, sha1hash_length):
        max_time = 0
        character = ""
        for j in range(0, 256):
            # Build the hmac to bruteforce with
            curr_input = known_bytes + struct.pack('B', j)
            curr_input += '\xff' * (sha1hash_length - num_uncovered - 1)
            # Craft the HTTP request
            args = { "file": file_name, "signature": curr_input.encode('hex') }
            url_data = urllib.urlencode(args)
            # Get the current time in milliseconds
            curr_time = time.time() * 1000
            try:
                response = urllib2.urlopen(urllib2.Request(server_url, url_data))
            except urllib2.URLError, e:
                # Get the time now
                response_time = time.time() * 1000
                difference = response_time - curr_time
                # Check if we've found a new max
                if difference > max_time:
                    max_time = difference
                    character = struct.pack('B', j)
            else:
                return curr_input.encode("hex")
        known_bytes += character
        print("uncovered a new character, known_bytes: {}".format(known_bytes.encode("hex")))
        num_uncovered += 1
    return known_bytes.encode("hex")

if __name__ == "__main__":
    if test_server is not False:
        test()
    else:
        print("Go watch a Youtube video or something, this will take a really long time (~30 minutes or so)")
        hmac = crack_hmac("file")
        print("The hmac for {} is: {}".format("file", hmac))
