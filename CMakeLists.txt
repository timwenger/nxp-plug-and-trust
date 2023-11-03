cmake_minimum_required(VERSION 3.5.0)
project(nxp-mini-middleware)

SET(SIMW_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR})
include(simw_lib.cmake)

set(SCP_KEYS_PATH "\"/home/enersys-user/tims-scp-keys/\"")
set(SCP_KEYS_FILENAME "\"plain_scp.txt\"")
configure_file(
    "enersys-defines.h.in" #input
    ${CMAKE_CURRENT_SOURCE_DIR}/enersys-defines.h #output
    )

add_subdirectory(ecc_example)