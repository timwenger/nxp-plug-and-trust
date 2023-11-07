cmake_minimum_required(VERSION 3.5.0)
project(nxp-mini-middleware)
message("configuring project:\n" ${PROJECT_NAME} "\n")

set(SIMW_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR})
include(simw_lib.cmake)


### START EnerSys- specific defines ###
set(SCP_KEYS_PATH "\"/home/enersys-user/tims-scp-keys/\"")
set(SCP_KEYS_FILENAME "\"plain_scp.txt\"")
set(EDGELOCK_HOSTNAME "\"xvtvuubgrtr0k94q.device-link.edgelock2go.com\"")
set(CLAIMCODE "\"ZGFjYTMxNjMtOWVkNi00OWQwLThhMjUtN2QxZTM5MTA5ZDE3MDAwMDIwNTA=\"")
### END   EnerSys- specific defines ###


configure_file(
    "enersys-defines.h.in" #input
    ${CMAKE_CURRENT_SOURCE_DIR}/enersys-defines.h #output
    )

# for building on the imx (not raspberry pi)
set(SSS_HAVE_HOST_IMXLINUX ON)

add_subdirectory(ecc_example)

add_subdirectory(nxp_iot_agent)