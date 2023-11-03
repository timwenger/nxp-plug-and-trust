# Copyright 2019, 2020, 2021 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

PROJECT(nxp_iot_agent LANGUAGES C)

FILE(
    GLOB
    NXP_IOT_AGENT_FILES
    inc/*.h
    inc/*.h.in
    src/*.c
    src/protobuf/*.h
    src/protobuf/*.c
)

FILE(
GLOB
    NXP_IOT_AGENT_OPENSSL_FILES
    platform/openssl/*.h
    platform/openssl/*.h.in
    platform/openssl/*.c
)

set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} ${NXP_IOT_AGENT_OPENSSL_FILES})


ADD_LIBRARY(nxp_iot_agent ${NXP_IOT_AGENT_FILES})

IF(
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
ENDIF()

TARGET_INCLUDE_DIRECTORIES(
    nxp_iot_agent
    PUBLIC inc
    PUBLIC platform
    PUBLIC src/protobuf
)

TARGET_INCLUDE_DIRECTORIES(
    nxp_iot_agent
    PUBLIC port/default
)



TARGET_LINK_LIBRARIES(
nxp_iot_agent
${OPENSSL_LIBRARIES}
)

TARGET_INCLUDE_DIRECTORIES(
nxp_iot_agent
PUBLIC platform/openssl
)

TARGET_COMPILE_DEFINITIONS(nxp_iot_agent PRIVATE OPENSSL_LOAD_CONF)


TARGET_LINK_LIBRARIES(
    nxp_iot_agent
    se05x
)

TARGET_COMPILE_DEFINITIONS(nxp_iot_agent PRIVATE PB_FIELD_32BIT)


TARGET_LINK_LIBRARIES(
    nxp_iot_agent
    smCom
    ex_common
    SSS_APIs
    nxp_iot_agent_common
    ${LIBS_SYSTEM}
)

ADD_SUBDIRECTORY(ex)

IF(SSS_HAVE_HOST_PCLINUX OR SSS_HAVE_HOST_IMXLINUX)
    INSTALL(TARGETS nxp_iot_agent DESTINATION lib)
ENDIF()

# TODO: Get rid of -Wno-format -Wno-format-security

IF("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  TARGET_COMPILE_OPTIONS(
    ${PROJECT_NAME}
    PRIVATE -Wno-error=format
    PRIVATE -Wno-format
    PRIVATE -Wno-error=format-security
    PRIVATE -Wno-format-security
    PRIVATE -Wno-address-of-packed-member
    PRIVATE -Wno-incompatible-pointer-types
    )
ENDIF()
