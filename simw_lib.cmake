#
# Copyright 2023 NXP
# SPDX-License-Identifier: Apache-2.0
#

set(
    SIMW_SE_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/sss/ex/src/ex_sss_boot.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sss/ex/src/ex_sss_boot_connectstring.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sss/ex/src/ex_sss_se05x.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sss/ex/src/ex_sss_se05x_auth.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sss/src/fsl_sss_apis.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sss/src/fsl_sss_util_asn1_der.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sss/src/fsl_sss_util_rsa_sign_utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sss/src/se05x/fsl_sss_se05x_apis.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sss/src/se05x/fsl_sss_se05x_mw.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sss/src/se05x/fsl_sss_se05x_policy.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hostlib/hostLib/libCommon/infra/global_platf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hostlib/hostLib/libCommon/infra/sm_apdu.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hostlib/hostLib/libCommon/infra/sm_connect.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hostlib/hostLib/libCommon/infra/sm_errors.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hostlib/hostLib/libCommon/infra/sm_printf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hostlib/hostLib/libCommon/log/nxLog.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hostlib/hostLib/libCommon/smCom/smCom.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hostlib/hostLib/platform/rsp/se05x_reset.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hostlib/hostLib/platform/generic/sm_timer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hostlib/hostLib/se05x/src/se05x_ECC_curves.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hostlib/hostLib/se05x/src/se05x_mw.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hostlib/hostLib/se05x/src/se05x_tlv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hostlib/hostLib/se05x_03_xx_xx/se05x_APDU.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hostlib/hostLib/libCommon/smCom/smComT1oI2C.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hostlib/hostLib/libCommon/smCom/T1oI2C/phNxpEse_Api.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hostlib/hostLib/libCommon/smCom/T1oI2C/phNxpEsePal_i2c.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hostlib/hostLib/libCommon/smCom/T1oI2C/phNxpEseProto7816_3.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hostlib/hostLib/platform/linux/i2c_a7.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sss/src/openssl/fsl_sss_openssl_apis.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sss/src/keystore/keystore_cmn.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sss/src/keystore/keystore_openssl.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sss/src/keystore/keystore_pc.c
)

set(
    SIMW_SE_AUTH_SOURCES
    ##### Authenticated session to se05x
    ${CMAKE_CURRENT_SOURCE_DIR}/sss/ex/src/ex_sss_scp03_auth.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sss/src/se05x/fsl_sss_se05x_eckey.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sss/src/se05x/fsl_sss_se05x_scp03.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hostlib/hostLib/libCommon/nxScp/nxScp03_Com.c
)

file(
    GLOB
    SIMW_INC_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/sss/inc
    ${CMAKE_CURRENT_SOURCE_DIR}/sss/port/default
    ${CMAKE_CURRENT_SOURCE_DIR}/sss/ex/src
    ${CMAKE_CURRENT_SOURCE_DIR}/sss/ex/inc
    ${CMAKE_CURRENT_SOURCE_DIR}/hostlib/hostLib/inc
    ${CMAKE_CURRENT_SOURCE_DIR}/hostlib/hostLib/libCommon/infra
    ${CMAKE_CURRENT_SOURCE_DIR}/hostlib/hostLib/libCommon/smCom
    ${CMAKE_CURRENT_SOURCE_DIR}/hostlib/hostLib/libCommon/log
    ${CMAKE_CURRENT_SOURCE_DIR}/hostlib/hostLib/libCommon/smCom/T1oI2C
    ${CMAKE_CURRENT_SOURCE_DIR}/hostlib/hostLib/se05x_03_xx_xx
    ${CMAKE_CURRENT_SOURCE_DIR}/hostlib/hostLib/platform/inc
    ${CMAKE_CURRENT_SOURCE_DIR}/hostlib/hostLib/libCommon/smCom
)

ADD_DEFINITIONS(-fPIC)
ADD_DEFINITIONS(-DSSS_USE_FTR_FILE)
ADD_DEFINITIONS(-DSMCOM_T1oI2C)
ADD_DEFINITIONS(-DT1oI2C)
ADD_DEFINITIONS(-DT1oI2C_UM11225)
ADD_DEFINITIONS(-DT1OI2C_RETRY_ON_I2C_FAILED)

#ADD_DEFINITIONS(-DFLOW_VERBOSE)

INCLUDE(simwlib_cmake_options.cmake)
