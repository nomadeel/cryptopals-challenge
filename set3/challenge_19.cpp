#include <curses.h>
#include <string>
#include <algorithm>
#include <vector>
#include <fstream>
#include <utility>
#include <cassert>

#include "cryptopp/cryptlib.h"
#include "cryptopp/base64.h"
#include "cryptopp/filters.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"

/*
 * This is a simple ncurses program to tackle Set 3, Challenge 19 of Cryptopals.
 * Instead of having to automate the cracking of the ciphers, this application
 * allows you to do it while giving immediate feedback. This makes it a lot
 * easier to solve by hand.
 *
 * Controls:
 *      - Keypad: moves the cursor in the corresponding direction by 1 unit
 *      - Printable characters, a-zA-Z0-9 and punctuation: inputs the character
 *       and solves the line. In case that a particular character results in a
 *       non-printable character, that character will be painted red.
 *       - Esc: quits the application, Ctrl - C also works
 *       - Backspace: removes a character and all other characters in the same column
 *
 * Credits to callorico of Github, https://github.com/callorico/cryptopals/blob/master/challenge19.py.
 * Ported to C++ from his Python code.
 */

const unsigned int BLOCK_SIZE = 16;

// Cursor position for ncurses
int x;
int y;

std::string xor_strings(std::string &a, std::string &b) {
    std::string output;
    output.reserve(a.size());

    for (auto i = 0U; i < a.size(); ++i) {
        output += (a[i] ^ b[i]);
    }

    return output;
}

std::string ctr_cipher(std::string &input, CryptoPP::byte *key, unsigned long long nonce) {
    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption e;
    e.SetKey(key, 16);

    unsigned long long counter = 0;
    unsigned int num_blocks = (input.size() / BLOCK_SIZE) + (input.size() % BLOCK_SIZE != 0);
    std::string keystream;
    std::string output;

    for (auto i = 0U; i < num_blocks; ++i) {
        std::string curr_block = input.substr(i*BLOCK_SIZE, BLOCK_SIZE);
        // Build the strings to be encrypted
        std::string input_stream (reinterpret_cast<char *>(&nonce), sizeof nonce);
        input_stream.append(reinterpret_cast<char *>(&counter), sizeof counter);
        CryptoPP::StringSource ss1(input_stream, true,
                new CryptoPP::StreamTransformationFilter(e,
                    new CryptoPP::StringSink(keystream),
                    CryptoPP::BlockPaddingSchemeDef::NO_PADDING)
        );
        output += xor_strings(curr_block, keystream);
        // Clear the keystream string and advance the counter
        keystream.clear();
        ++counter;
    }

    return output;
}

std::pair<std::vector<std::string>, unsigned int> parse_file(void) {
    std::vector<std::string> output_vec;

    std::ifstream in {"19.txt"};

    std::string s;

    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::SecByteBlock key(16);
    // Generate the consistent key and base64 decode the unknown string
    prng.GenerateBlock(key, key.size());

    unsigned int max_length = 0;

    while (in >> s) {
        std::string decoded_input = "";
        CryptoPP::StringSource ss(s, true,
                new CryptoPP::Base64Decoder(
                    new CryptoPP::StringSink(decoded_input)
                    )
        );
        std::string ciphertext = ctr_cipher(decoded_input, key, 0);
        output_vec.push_back(ciphertext);
        if (ciphertext.length() > max_length) {
            max_length = ciphertext.length();
        }
    }

    return std::make_pair(output_vec, max_length);
}

void init_ncurses(void) {
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    start_color();
    init_pair(1, COLOR_RED, COLOR_RED);
}

void render(std::string &keystream, std::vector<bool> &key_field, std::vector<std::string> &ciphertext_vec) {
    move(0, 0);
    for (auto &s : ciphertext_vec) {
        unsigned int pos = 0;
        for (auto &c : s) {
            if (key_field[pos]) {
                char output = c ^ keystream[pos];
                if (' ' <= output && output <= '~') {
                    addch(output);
                } else {
                    addch(' ' | COLOR_PAIR(1));
                }
            } else {
                addch('*');
            }
            ++pos;
        }
        addch('\n');
    }
    move(y, x);
    refresh();
}

int clamp(int new_val, int min, int max) {
    if (new_val < min) {
        return min;
    } else if (new_val >= max) {
        return max - 1;
    } else {
        return new_val;
    }
}

void move(int &x, int &y, int x_delta, int y_delta, std::vector<std::string> &ciphertext_vec) {
    y = clamp(y + y_delta, 0, ciphertext_vec.size());
    x = clamp(x + x_delta, 0, ciphertext_vec[y].length());
}

void set_letter(int x, int y, char c, std::string &keystream, std::vector<bool> &key_field,
                std::vector<std::string> &ciphertext_vec) {
    assert(y < ciphertext_vec.size());
    assert(x < ciphertext_vec[y].length());
    assert(x < keystream.length());
    if (c == 0) {
        // Deleting a letter
        keystream[x] = '\x00';
        key_field[x] = false;
    } else {
        keystream[x] = ciphertext_vec[y][x] ^ c;
        key_field[x] = true;
    }
}

void event_loop(unsigned int max_length, std::vector<std::string> &ciphertext_vec) {
    std::string keystream(max_length, '\x00');
    std::vector<bool> key_field(max_length);
    x = 0;
    y = 0;
    render(keystream, key_field, ciphertext_vec);

    int c;
    while (c = getch()) {
        switch (c) {
            case 27:
                endwin();
                return;
                break;
            case KEY_RIGHT:
                move(x, y, 1, 0, ciphertext_vec);
                break;
            case KEY_LEFT:
                move(x, y, -1, 0, ciphertext_vec);
                break;
            case KEY_UP:
                move(x, y, 0, -1, ciphertext_vec);
                break;
            case KEY_DOWN:
                move(x, y, 0, 1, ciphertext_vec);
                break;
            case KEY_BACKSPACE:
                set_letter(x, y, 0, keystream, key_field, ciphertext_vec);
                break;
            default:
                // Check that the key is printable
                if (' ' <= c && c <= '~') {
                    set_letter(x, y, c, keystream, key_field, ciphertext_vec);
                }
                break;
        }
        render(keystream, key_field, ciphertext_vec);
    }
}

int main(void) {
    std::vector<std::string> ciphertext_vec;
    auto p = parse_file();
    ciphertext_vec = p.first;
    unsigned int max_length = p.second;

    init_ncurses();

    event_loop(max_length, ciphertext_vec);
}
