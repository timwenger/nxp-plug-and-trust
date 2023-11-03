# Copyright 2020, 2021 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# TODO: Get rid of -Wno-format -Wno-format-security

IF(CMAKE_COMPILER_IS_GNUCC)
  ADD_DEFINITIONS("-Wno-unused-function -Wno-format -Wno-format-security")
ENDIF()


###################### nxp_iot_agent_demo

PROJECT(nxp_iot_agent_demo)

INCLUDE_DIRECTORIES(../inc/)

FILE(
    GLOB
    iot_agent_demo_files
    ../inc/iot_agent_config.h
    utils/iot_agent_claimcode_inject.c
    iot_agent_demo.c
)

IF(SSS_HAVE_HOSTCRYPTO_OPENSSL)
    SET(HEADER_FILES
        ../inc/iot_agent_mqtt_paho.h
    )
    LIST(
        APPEND
        iot_agent_demo_files
        utils/iot_agent_mqtt_paho.c
        ${SIMW_TOP_DIR}/ext/amazon-freertos/libraries/3rdparty/jsmn/jsmn.c
    )
    TARGET_INCLUDE_DIRECTORIES(
        nxp_iot_agent
        PUBLIC
        ${SIMW_TOP_DIR}/ext/amazon-freertos/libraries/3rdparty/jsmn
    )
ENDIF()

IF(SSS_HAVE_HOST_FRDMK64F OR SSS_HAVE_HOST_EVKMIMXRT1060 OR SSS_HAVE_HOST_EVKMIMXRT1170)
    FILE(
        GLOB
        iot_agent_demo_port_files
        ../inc/iot_agent_network.h
        network/iot_agent_network_lwip.c
        utils/iot_agent_mqtt_freertos.c
    )
ENDIF()

IF(SSS_HAVE_HOST_LPCXPRESSO55S)
    FILE(
        GLOB
        iot_agent_demo_port_files
        ../inc/iot_agent_network.h
        network/iot_agent_network_lpc_mwm.c
        utils/iot_agent_mqtt_freertos.c
    )
ENDIF()

ADD_EXECUTABLE(${PROJECT_NAME} ${KSDK_STARTUP_FILE}
    ${iot_agent_demo_files}
    ${iot_agent_demo_port_files}
)


IF(BUILD_SHARED_LIBS)
    IF(SSS_HAVE_HOSTCRYPTO_OPENSSL)
        TARGET_LINK_LIBRARIES(
            ${PROJECT_NAME}
                paho-mqtt3cs
        )
    ENDIF()
ELSE()
    IF(SSS_HAVE_HOSTCRYPTO_OPENSSL)
        TARGET_LINK_LIBRARIES(
            ${PROJECT_NAME}
                paho-mqtt3cs-static
        )
    ENDIF()
ENDIF()


TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    SSS_APIs
    nxp_iot_agent
)

CREATE_BINARY(${PROJECT_NAME})

IF(SSS_HAVE_HOST_LINUX_LIKE)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION bin)
ENDIF()

###################### claimcode_inject

IF(SSS_HAVE_HOSTCRYPTO_OPENSSL AND SSS_HAVE_APPLET_SE05X_IOT)
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
    CREATE_BINARY(${PROJECT_NAME})
ENDIF()

IF(SSS_HAVE_HOST_LINUX_LIKE)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION bin)
ENDIF()

###################### remote_provisioning_client

IF(SSS_HAVE_APPLET_SE05X_IOT)
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

    CREATE_BINARY(${PROJECT_NAME})
ENDIF()


###################### remote_provisioning_client_lib

IF(SSS_HAVE_APPLET_SE05X_IOT)
    PROJECT(rtp_client)

    IF(SSS_HAVE_HOST_PCLINUX OR SSS_HAVE_HOST_IMXLINUX)
        FIND_PACKAGE(Threads)
    ENDIF()

    SET(HEADER_FILES
        ../inc/iot_agent_rtp_client.h
    )

   ADD_LIBRARY(rtp_client STATIC ${KSDK_STARTUP_FILE}
        utils/iot_agent_rtp_client.c
        ${iot_agent_demo_port_files}
    )

    TARGET_LINK_LIBRARIES(
        ${PROJECT_NAME}
        SSS_APIs
        nxp_iot_agent
        ${LIBS_SYSTEM}
    )

ENDIF()