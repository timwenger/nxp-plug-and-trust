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
        *.c
        ../protobuf/*.h
        ../protobuf/*.c
)


add_library(${PROJECT_NAME} ${NXP_IOT_AGENT_COMMON_FILES})

target_include_directories(
    ${PROJECT_NAME}
    PUBLIC ../../inc
    PUBLIC ../../platform
    PUBLIC ../protobuf
    PUBLIC ${COMMON_INC_DIRS}
)

target_compile_definitions(${PROJECT_NAME} PRIVATE PB_FIELD_32BIT)

target_link_libraries(
    ${PROJECT_NAME}
    se05x
    smCom
    SSS_APIs
    ex_common
)

if(SSS_HAVE_HOST_IMXLINUX)
    install(TARGETS ${PROJECT_NAME} DESTINATION lib)
endif()
