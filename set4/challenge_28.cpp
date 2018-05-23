#include <iostream>
#include <string>
#include <cassert>

#include "cryptopp/cryptlib.h"
#include "cryptopp/filters.h"
#include "cryptopp/sha.h"
#include "cryptopp/hex.h"

bool validate_mac(std::string &input, std::string &key, std::string &mac) {
    std::string key_prefixed_message = key + input;
    std::string hash;

    CryptoPP::SHA1 sha1;
    CryptoPP::StringSource ss1(key_prefixed_message, true,
            new CryptoPP::HashFilter(sha1,
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(hash)
                )
            )
    );

    return (mac == hash) ? true : false;
}

int main(void) {
    std::string message = "hello world";
    std::string key = "hello world";
    
    std::string key_mac;

    CryptoPP::SHA1 sha1;
    CryptoPP::StringSource ss1(key + message, true,
            new CryptoPP::HashFilter(sha1,
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(key_mac)
                )
            )
    );

    std::string bad_message = "Hello world";
    std::string bad_mac = key_mac;
    bad_mac[0] = '\x42';
    assert(validate_mac(bad_message, key, key_mac) == false);
    assert(validate_mac(message, key, bad_mac) == false);
    std::cout << "Assertions passed\n";
}
