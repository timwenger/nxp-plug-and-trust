# Copyright 2019, 2020, 2021 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

PROJECT(nxp_iot_agent LANGUAGES C)

message("configuring project:\n" ${PROJECT_NAME} "\n")

set(IOT_AGENT_DIR  ${SIMW_LIB_DIR}/nxp_iot_agent)

file(
    GLOB
    NXP_IOT_AGENT_FILES
    inc/*.h
    inc/*.h.in
    src/*.c
    src/protobuf/*.h
    src/protobuf/*.c
    # iot agent openssl files
    platform/openssl/*.h
    platform/openssl/*.h.in
    platform/openssl/*.c
)

add_library(nxp_iot_agent ${NXP_IOT_AGENT_FILES})

target_include_directories(
    nxp_iot_agent
    PUBLIC inc
    PUBLIC platform
    PUBLIC src/protobuf
    PUBLIC port/default
    PUBLIC platform/openssl
    PUBLIC ${SIMW_INC_DIR} # includes from the common middleware libraries
)

target_link_libraries(
    nxp_iot_agent
    ${OPENSSL_LIBRARIES}
    se05x
    smCom
    ex_common
    SSS_APIs
    nxp_iot_agent_common
    ${LIBS_SYSTEM}
)

target_compile_definitions(nxp_iot_agent PRIVATE OPENSSL_LOAD_CONF)
# PB = protocol buffer
target_compile_definitions(nxp_iot_agent PRIVATE PB_FIELD_32BIT)


add_subdirectory(src)
add_subdirectory(ex)

if(SSS_HAVE_HOST_IMXLINUX)
    install(TARGETS nxp_iot_agent DESTINATION lib)
endif()


# setting the compiler warning options
# not sure what compiler is used for G2. 
# on rpi, /usr/bin/cc is used for C, and /usr/bin/c++ is used for C++

if(
    CMAKE_CXX_COMPILER
    MATCHES
    ".*clang"
    OR CMAKE_CXX_COMPILER_ID
       STREQUAL
       "AppleClang"
)
    TARGET_COMPILE_OPTIONS(
    ${PROJECT_NAME}
    PUBLIC -Wno-format
    PUBLIC -Wno-error=format)
endif()

# NXP TODO: Get rid of -Wno-format -Wno-format-security

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  TARGET_COMPILE_OPTIONS(
    ${PROJECT_NAME}
    PRIVATE -Wno-error=format
    PRIVATE -Wno-format
    PRIVATE -Wno-error=format-security
    PRIVATE -Wno-format-security
    PRIVATE -Wno-address-of-packed-member
    PRIVATE -Wno-incompatible-pointer-types
    )
endif()
