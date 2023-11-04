# Copyright 2019, 2021 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

PROJECT(nxp_iot_agent_common LANGUAGES C)
message("configuring project:\n" ${PROJECT_NAME} "\n")


FILE(
    GLOB
        NXP_IOT_AGENT_COMMON_FILES
        ../../inc/*.h
        ../../inc/*.h.in
        *.c
        ../protobuf/*.h
        ../protobuf/*.c
)


ADD_LIBRARY(nxp_iot_agent_common ${NXP_IOT_AGENT_COMMON_FILES})

# probably should be removed, since it's defined below again as private
TARGET_COMPILE_DEFINITIONS(
    ${PROJECT_NAME}
    PUBLIC PB_FIELD_32BIT
)

TARGET_INCLUDE_DIRECTORIES(
    nxp_iot_agent_common
    PUBLIC ../../inc
    PUBLIC ../../platform
    PUBLIC ../protobuf
    PUBLIC ../../../semslite/lib/inc
    PUBLIC port/default
    PUBLIC ${SIMW_INC_DIR} # includes from the common middleware libraries
)

TARGET_LINK_LIBRARIES(
    nxp_iot_agent_common
    se05x
)

TARGET_COMPILE_DEFINITIONS(nxp_iot_agent_common PRIVATE PB_FIELD_32BIT)

TARGET_LINK_LIBRARIES(
    nxp_iot_agent_common
    smCom
    SSS_APIs
    ex_common
)


IF(SSS_HAVE_HOST_IMXLINUX)
    INSTALL(TARGETS nxp_iot_agent_common DESTINATION lib)
ENDIF()
