cmake_minimum_required(VERSION 3.10)
project(vscode)

find_package(OpenSSL REQUIRED)
set(CMAKE_CXX_STANDARD 17)


add_executable(SHA main.cpp sha256.h sha256.c)
target_link_libraries(SHA OpenSSL::SSL OpenSSL::Crypto) #ищет ssl на компьютере.