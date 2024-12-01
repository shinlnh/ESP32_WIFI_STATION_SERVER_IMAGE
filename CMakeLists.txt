# The following five lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(WIFI_STATION_SERVER)

target_add_binary_data(${CMAKE_PROJECT_NAME}.elf "image/3.jpeg" TEXT)