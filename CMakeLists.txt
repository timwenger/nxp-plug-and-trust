cmake_minimum_required(VERSION 3.5.0)
project(nxp-mini-middleware)
message("configuring project:\n" ${PROJECT_NAME} "\n")

set(SIMW_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR})
include(simw_lib.cmake)

# for building on the imx (not raspberry pi)
set(SSS_HAVE_HOST_IMXLINUX ON)

add_subdirectory(ecc_example)

add_subdirectory(nxp_iot_agent)