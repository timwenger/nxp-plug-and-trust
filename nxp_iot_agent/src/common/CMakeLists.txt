# Copyright 2019, 2021 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

project(nxp_iot_agent_common LANGUAGES C)
message("configuring project:\n" ${PROJECT_NAME} "\n")


file(
    GLOB
        NXP_IOT_AGENT_COMMON_FILES
        ../../inc/*.h
        ../../inc/*.h.in
        *.c
        ../protobuf/*.h
        ../protobuf/*.c
)


add_library(nxp_iot_agent_common ${NXP_IOT_AGENT_COMMON_FILES})

# probably should be removed, since it's defined below again as private
target_compile_definitions(
    ${PROJECT_NAME}
    PUBLIC PB_FIELD_32BIT
)

target_include_directories(
    nxp_iot_agent_common
    PUBLIC ../../inc
    PUBLIC ../../platform
    PUBLIC ../protobuf
    PUBLIC ../../../semslite/lib/inc
    PUBLIC port/default
    PUBLIC ${SIMW_INC_DIR} # includes from the common middleware libraries
)

target_link_libraries(
    nxp_iot_agent_common
    se05x
)

target_compile_definitions(nxp_iot_agent_common PRIVATE PB_FIELD_32BIT)

target_link_libraries(
    nxp_iot_agent_common
    smCom
    SSS_APIs
    ex_common
)


if(SSS_HAVE_HOST_IMXLINUX)
    install(TARGETS nxp_iot_agent_common DESTINATION lib)
endif()
