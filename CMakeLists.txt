cmake_minimum_required(VERSION 3.12)
project(idRehash)

set(CMAKE_C_STANDARD 99)

file(GLOB SOURCES
        ./main.c
        ./cvector/cvector.h
        ./cvector/cvector_utils.h
        ./farmhash-c/farmhash.c
        ./farmhash-c/farmhash.h
        )

set (CMAKE_C_FLAGS "-O2 -Wall -Wno-maybe-uninitialized -Werror")
add_executable(idRehash ${SOURCES})

target_link_libraries(idRehash ${CMAKE_DL_LIBS})
