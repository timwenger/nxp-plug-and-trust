cmake_minimum_required(VERSION 3.5.0)
project(nxp-mini-middleware)

include(simw_lib.cmake)

set(SCP_KEYS_PATH "/home/enersys-user/tims-scp-keys/")
set(SCP_KEYS_FILENAME "plain_scp.txt")
add_subdirectory(configurations)

add_subdirectory(ecc_example)