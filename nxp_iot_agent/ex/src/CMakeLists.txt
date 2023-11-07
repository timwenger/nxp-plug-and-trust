# Copyright 2020, 2021 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# NXP TODO: Get rid of -Wno-format -Wno-format-security

if(CMAKE_COMPILER_IS_GNUCC)
  add_definitions("-Wno-unused-function -Wno-format -Wno-format-security")
endif()


###################### nxp_iot_agent_demo

project(nxp_iot_agent_demo)

message("configuring project:\n" ${PROJECT_NAME} "\n")

include_directories(../inc/)



target_include_directories(
    nxp_iot_agent
    PUBLIC ${IOT_AGENT_DIR}/ext/jsmn
)

set(IOT_AGENT_DEMO_FILES
    ../inc/iot_agent_config.h
    utils/iot_agent_claimcode_inject.c
    iot_agent_demo.c
    ${IOT_AGENT_DIR}/ext/jsmn/jsmn.c
)

add_executable(${PROJECT_NAME}
    ${IOT_AGENT_DEMO_FILES}
)

target_link_libraries(
    ${PROJECT_NAME}
    SSS_APIs
    nxp_iot_agent
)

install(TARGETS ${PROJECT_NAME} DESTINATION bin)


###################### claimcode_inject

project(claimcode_inject)

add_executable(${PROJECT_NAME}
    utils/iot_agent_claimcode_inject.c
    apps/claimcode_inject_demo.c
)

target_link_libraries(
    ${PROJECT_NAME}
    nxp_iot_agent
    SSS_APIs
)

install(TARGETS ${PROJECT_NAME} DESTINATION bin)


###################### remote_provisioning_client

project(remote_provisioning_client)

add_executable(${PROJECT_NAME}
    apps/remote_provisioning_client.c
)

target_link_libraries(
    ${PROJECT_NAME}
    SSS_APIs
    rtp_client
    nxp_iot_agent
)

###################### remote_provisioning_client_lib

project(rtp_client)

if(SSS_HAVE_HOST_IMXLINUX)
    find_package(Threads)
endif()

add_library(rtp_client STATIC
    utils/iot_agent_rtp_client.c
)

target_link_libraries(
    ${PROJECT_NAME}
    SSS_APIs
    nxp_iot_agent
)