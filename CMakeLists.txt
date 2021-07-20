cmake_minimum_required(VERSION 3.12)
project(idRehash)

set(CMAKE_C_STANDARD 99)

file(GLOB SOURCES
        ./main.c
        ./farmhash-c/farmhash.c
        ./farmhash-c/farmhash.h
        )

find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB REQUIRED glib-2.0)
include_directories(${GLIB_INCLUDE_DIRS})

set (CMAKE_C_FLAGS "-O2 -DNDEBUG")
add_executable(idRehash ${SOURCES})

target_link_libraries(idRehash ${GLIB_LDFLAGS} ${CMAKE_DL_LIBS})
