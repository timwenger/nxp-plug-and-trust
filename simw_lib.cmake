#
# Copyright 2023 NXP
# SPDX-License-Identifier: Apache-2.0
#

FILE(
    GLOB
    SIMW_SE_SOURCES
    sss/ex/src/ex_sss_boot.c
    sss/ex/src/ex_sss_boot_connectstring.c
    sss/ex/src/ex_sss_se05x.c
    sss/ex/src/ex_sss_se05x_auth.c
    sss/src/*.c
    sss/src/se05x/fsl_sss_se05x_apis.c
    sss/src/se05x/fsl_sss_se05x_mw.c
    sss/src/se05x/fsl_sss_se05x_policy.c
    hostlib/hostLib/libCommon/infra/*.c
    hostlib/hostLib/libCommon/log/nxLog.c
    hostlib/hostLib/libCommon/smCom/smCom.c
    hostlib/hostLib/platform/rsp/se05x_reset.c
    hostlib/hostLib/platform/generic/sm_timer.c
    hostlib/hostLib/se05x/src/se05x_ECC_curves.c
    hostlib/hostLib/se05x/src/se05x_mw.c
    hostlib/hostLib/se05x/src/se05x_tlv.c
    hostlib/hostLib/se05x_03_xx_xx/se05x_APDU.c
    hostlib/hostLib/libCommon/smCom/smComT1oI2C.c
    hostlib/hostLib/libCommon/smCom/T1oI2C/*.c
    hostlib/hostLib/platform/linux/i2c_a7.c
    sss/src/openssl/fsl_sss_openssl_apis.c
    sss/src/keystore/keystore_cmn.c
    sss/src/keystore/keystore_openssl.c
    sss/src/keystore/keystore_pc.c
)

FILE(
    GLOB
    SIMW_SE_AUTH_SOURCES
    ##### Authenticated session to se05x
    sss/ex/src/ex_sss_scp03_auth.c
    sss/src/se05x/fsl_sss_se05x_eckey.c
    sss/src/se05x/fsl_sss_se05x_scp03.c
    hostlib/hostLib/libCommon/nxScp/nxScp03_Com.c
)

FILE(
    GLOB
    SIMW_INC_DIR
    ${SIMW_LIB_DIR}
    sss/inc
    sss/port/default
    sss/ex/src
    sss/ex/inc
    hostlib/hostLib/inc
    hostlib/hostLib/libCommon/infra
    hostlib/hostLib/libCommon/smCom
    hostlib/hostLib/libCommon/log
    hostlib/hostLib/libCommon/smCom/T1oI2C
    hostlib/hostLib/se05x_03_xx_xx
    hostlib/hostLib/platform/inc
    hostlib/hostLib/libCommon/smCom
)

ADD_DEFINITIONS(-fPIC)
ADD_DEFINITIONS(-DSSS_USE_FTR_FILE)
ADD_DEFINITIONS(-DSMCOM_T1oI2C)
ADD_DEFINITIONS(-DT1oI2C)
ADD_DEFINITIONS(-DT1oI2C_UM11225)
ADD_DEFINITIONS(-DT1OI2C_RETRY_ON_I2C_FAILED)

#ADD_DEFINITIONS(-DFLOW_VERBOSE)

INCLUDE(simwlib_cmake_options.cmake)
