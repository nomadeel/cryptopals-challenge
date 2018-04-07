#include <string>
#include <fstream>
#include <iostream>

#include "cryptopp/cryptlib.h"
#include "cryptopp/base64.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"

int main(void) {
    CryptoPP::byte key[16] = {'Y','E','L','L','O','W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'};
    CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption d;
    d.SetKey(key, 16);

    std::string hexstring, s;
    std::string input;

    std::ifstream in;
    in.open("7.txt");

    while (in >> s) {
        input += s;
    }

    CryptoPP::StringSource ss1(input, true,
            new CryptoPP::Base64Decoder(
                new CryptoPP::StringSink(hexstring)
            )
    );

    std::string deciphered;

    CryptoPP::StringSource ss2(hexstring, true,
        new CryptoPP::StreamTransformationFilter(d,
            new CryptoPP::StringSink(deciphered)
        )
    );

    std::cout << "Deciphered text:\n" << deciphered << "\n";
}
