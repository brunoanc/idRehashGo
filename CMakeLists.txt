cmake_minimum_required(VERSION 3.12)
project(idRehash)

set(CMAKE_C_STANDARD 99)

file(GLOB SOURCES
        ./main.c
        ./cvector/cvector.h
        ./cvector/cvector_utils.h
        ./farmhash-c/farmhash.h
        ./fts/fts.c
        ./fts/fts.h
        ./ooz/ooz.h
        )

if(DEFINED ENV{IDREHASHLINUX_STATIC})
        set (CMAKE_C_FLAGS "-O2 -static -s -Wall -Wno-maybe-uninitialized -Werror")
else()
        set (CMAKE_C_FLAGS "-O2 -s -Wall -Wno-maybe-uninitialized -Werror")
endif()

set (CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS}")
add_executable(idRehash ${SOURCES})

set_target_properties(idRehash PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(idRehash ${CMAKE_SOURCE_DIR}/farmhash-c/farmhash.a ${CMAKE_SOURCE_DIR}/ooz/libooz.a)
