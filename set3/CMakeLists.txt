add_executable(challenge_17 challenge_17.cpp)
target_link_libraries(challenge_17 cryptopp)

add_executable(challenge_18 challenge_18.cpp)
target_link_libraries(challenge_18 cryptopp)

find_library(NCURSES ncurses)
if (NCURSES)
    add_executable(challenge_19 challenge_19.cpp)
    target_link_libraries(challenge_19 cryptopp)
    target_link_libraries(challenge_19 ncurses)
else()
    string(ASCII 27 ESCAPE)
    message(WARNING "${ESCAPE}[1mlibncurses not found, will not be building set 3 challenge 19${ESCAPE}[0m")
endif()

add_executable(challenge_20 challenge_20.cpp)
target_link_libraries(challenge_20 cryptopp)

add_executable(challenge_21 challenge_21.cpp mersenne_twister.cpp)

add_executable(challenge_22 challenge_22.cpp mersenne_twister.cpp)

add_executable(challenge_23 challenge_23.cpp mersenne_twister.cpp)

add_executable(challenge_24 challenge_24.cpp mersenne_twister.cpp)
target_link_libraries(challenge_24 cryptopp)
