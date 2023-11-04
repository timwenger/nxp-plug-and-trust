# Copyright 2020, 2021 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# NXP TODO: Get rid of -Wno-format -Wno-format-security

IF(CMAKE_COMPILER_IS_GNUCC)
  ADD_DEFINITIONS("-Wno-unused-function -Wno-format -Wno-format-security")
ENDIF()


###################### nxp_iot_agent_demo

PROJECT(nxp_iot_agent_demo)

message("configuring project:\n" ${PROJECT_NAME} "\n")

INCLUDE_DIRECTORIES(../inc/)

FILE(
    GLOB
    iot_agent_demo_files
    ../inc/iot_agent_config.h
    utils/iot_agent_claimcode_inject.c
    iot_agent_demo.c
    utils/iot_agent_mqtt_paho.c
    ${IOT_AGENT_DIR}/ext/jsmn/jsmn.c
)

SET(HEADER_FILES
    ../inc/iot_agent_mqtt_paho.h
)

target_include_directories(
    nxp_iot_agent
    PUBLIC ${IOT_AGENT_DIR}/ext/jsmn
)

ADD_EXECUTABLE(${PROJECT_NAME}
    ${iot_agent_demo_files}
    ${iot_agent_demo_port_files}
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    SSS_APIs
    nxp_iot_agent
    paho-mqtt3cs-static
)

INSTALL(TARGETS ${PROJECT_NAME} DESTINATION bin)


###################### claimcode_inject

PROJECT(claimcode_inject)

SET(HEADER_FILES
    ../inc/iot_agent_claimcode_inject.h
    )

ADD_EXECUTABLE(${PROJECT_NAME}
    utils/iot_agent_claimcode_inject.c
    apps/claimcode_inject_demo.c
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    nxp_iot_agent
    SSS_APIs
)

INSTALL(TARGETS ${PROJECT_NAME} DESTINATION bin)


###################### remote_provisioning_client

PROJECT(remote_provisioning_client)

ADD_EXECUTABLE(${PROJECT_NAME}
    apps/remote_provisioning_client.c
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    SSS_APIs
    rtp_client
    nxp_iot_agent
)

###################### remote_provisioning_client_lib

PROJECT(rtp_client)

IF(SSS_HAVE_HOST_IMXLINUX)
    FIND_PACKAGE(Threads)
ENDIF()

SET(HEADER_FILES
    ../inc/iot_agent_rtp_client.h
)

ADD_LIBRARY(rtp_client STATIC
    utils/iot_agent_rtp_client.c
    ${iot_agent_demo_port_files}
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    SSS_APIs
    nxp_iot_agent
    ${LIBS_SYSTEM}
)