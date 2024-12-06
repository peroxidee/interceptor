cmake_minimum_required(VERSION 3.30)
project(interceptor C)

set(CMAKE_C_STANDARD 11)

add_executable(interceptor hooker/main.c
        dll/blackjack.c
        other/enum.c)
