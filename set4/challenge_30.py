#!/usr/bin/env python2

import md4
import os
import sha1
import struct
import random

# key = os.urandom(random.randint(3, 30))
key = os.urandom(16)

def validate_mac(message, key, mac):
    output_mac = md4.md4().update(key + message).digest()
    if output_mac == mac:
        return True
    else:
        return False 

def md4_pad(message):
    padding = ""

    # Add a byte with 1 in the MSB
    padding += "\x80"

    # Pad the string until it is a multiple of 64 bytes with 2 words open
    padding += '\x00' * ((56 - ((len(message) + 1) % 64)) % 64)

    # Append the length of the bitstring in number of bits
    padding += struct.pack("<2I", (len(message) * 8) & 0xffffffff, ((len(message) * 8) >> 32) & 0xffffffff)

    return message + padding

def get_registers(mac):
    return struct.unpack("<4I", mac)

def md4_length_attack(message, mac, extension):
    registers = get_registers(mac)

    for i in range(0, 40):
        padded_text = md4_pad('A' * i + message)
        registers = struct.unpack("<4I", mac)
        extended_message = padded_text[i:] + extension
        forged_mac = md4.md4(registers[0], registers[1], registers[2], registers[3]).update(extension).digest(len(padded_text + extension) * 8)
        if validate_mac(extended_message, key, forged_mac) is True:
            return i, forged_mac

    return -1, ""

if __name__ == "__main__":
    message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    mac = md4.md4().update(key + message).digest()

    key_len, forged_mac = md4_length_attack(message, mac, ';admin=true')

    print("The key length is {} with a forged MAC of {}".format(key_len, forged_mac.encode('hex')))
