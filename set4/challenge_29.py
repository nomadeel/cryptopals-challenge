#!/usr/bin/env python2

import os
import sha1
import struct

key = os.urandom(16)

def validate_mac(message, key, mac):
    output_mac = sha1.Sha1Hash().update(key + message).hexdigest()
    if output_mac == mac:
        return True
    else:
        return False 

def sha1_pad(message):
    padding = ""

    # Add a byte with 1 in the MSB
    padding += "\x80"

    # Pad the string until it is a multiple of 64 bytes with 2 words open
    padding += '\x00' * ((56 - (len(message) + 1) % 64) % 64)

    # Append the length of the bitstring in number of bits, big endian style
    padding += struct.pack(">Q", (len(message) * 8))

    return message + padding

def get_registers(mac):
    return struct.unpack(">IIIII", mac)

def sha1_length_attack(message, mac, extension):
    registers = list(get_registers(mac))

    for i in xrange(0, 40):
        padded_text = sha1_pad(("A" * i) + message)
        forged_mac = sha1.Sha1Hash(h=registers, message_byte_length=len(padded_text)).update(extension).hexdigest()
        extended_message = padded_text[i:] + extension
        if validate_mac(extended_message, key, forged_mac) is True:
            return i, forged_mac

    return -1, ""

if __name__ == "__main__":
    message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    mac = sha1.Sha1Hash().update(key + message).digest()

    key_len, forged_mac = sha1_length_attack(message, mac, ";admin=true")

    print("The key length is {} with a forged MAC of {}".format(key_len, forged_mac))
