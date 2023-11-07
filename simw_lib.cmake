#
# Copyright 2023 NXP
# SPDX-License-Identifier: Apache-2.0
#

# files supporting the example program, (ie, with ex/ in the file path)
# are the first files listed, just to keep things clean

message("Running simw_lib.cmake: setting variables for libraries, source, and include files ")

set(SIMW_SE_SOURCES
    ${SIMW_LIB_DIR}/sss/ex/src/ex_sss_boot.c
    ${SIMW_LIB_DIR}/sss/ex/src/ex_sss_boot_connectstring.c
    ${SIMW_LIB_DIR}/sss/ex/src/ex_sss_se05x.c
    ${SIMW_LIB_DIR}/sss/ex/src/ex_sss_se05x_auth.c

    ${SIMW_LIB_DIR}/sss/src/fsl_sss_apis.c
    ${SIMW_LIB_DIR}/sss/src/fsl_sss_util_asn1_der.c
    ${SIMW_LIB_DIR}/sss/src/fsl_sss_util_rsa_sign_utils.c
    ${SIMW_LIB_DIR}/sss/src/se05x/fsl_sss_se05x_apis.c
    ${SIMW_LIB_DIR}/sss/src/se05x/fsl_sss_se05x_mw.c
    ${SIMW_LIB_DIR}/sss/src/se05x/fsl_sss_se05x_policy.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/infra/global_platf.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/infra/sm_apdu.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/infra/sm_connect.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/infra/sm_errors.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/infra/sm_printf.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/log/nxLog.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/smCom/smCom.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/platform/rsp/se05x_reset.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/platform/generic/sm_timer.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/se05x/src/se05x_ECC_curves.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/se05x/src/se05x_mw.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/se05x/src/se05x_tlv.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/se05x_03_xx_xx/se05x_APDU.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/smCom/smComT1oI2C.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/smCom/T1oI2C/phNxpEse_Api.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/smCom/T1oI2C/phNxpEsePal_i2c.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/smCom/T1oI2C/phNxpEseProto7816_3.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/platform/linux/i2c_a7.c
    ${SIMW_LIB_DIR}/sss/src/openssl/fsl_sss_openssl_apis.c
    ${SIMW_LIB_DIR}/sss/src/keystore/keystore_cmn.c
    ${SIMW_LIB_DIR}/sss/src/keystore/keystore_openssl.c
    ${SIMW_LIB_DIR}/sss/src/keystore/keystore_pc.c
)

set(SIMW_SE_AUTH_SOURCES
    # needed for authenticated sessions to se05x
    ${SIMW_LIB_DIR}/sss/ex/src/ex_sss_scp03_auth.c
    ${SIMW_LIB_DIR}/sss/src/se05x/fsl_sss_se05x_eckey.c
    ${SIMW_LIB_DIR}/sss/src/se05x/fsl_sss_se05x_scp03.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/nxScp/nxScp03_Com.c
)

set(COMMON_INC_DIRS
    ${SIMW_LIB_DIR}
    ${SIMW_LIB_DIR}/sss/inc
    # /sss/ex/inc dir are seemingly includes only needed for example programs, 
    # but they include type definitions that the iot agent itself uses
    ${SIMW_LIB_DIR}/sss/ex/inc
    ${SIMW_LIB_DIR}/sss/port/default
    ${SIMW_LIB_DIR}/hostlib/hostLib/inc
    ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/infra
    ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/smCom
    ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/log
    ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/smCom/T1oI2C
    ${SIMW_LIB_DIR}/hostlib/hostLib/se05x_03_xx_xx
    ${SIMW_LIB_DIR}/hostlib/hostLib/platform/inc
    ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/smCom
    ${SIMW_LIB_DIR}/hostlib/hostLib/tstUtil
)

set(SIMW_INC_DIR
    ${COMMON_INC_DIRS}
    ${SIMW_LIB_DIR}/sss/ex/src
)



# the "ssl" and "crypto" openssl libraries are needed for several projects
set(OPENSSL_LIBRARIES ssl crypto)
# these commands are only used for printing out the library locations, just for your information
find_library(SSL_PATH ssl)
find_library(CRYPTO_PATH crypto)
message("using ssl library file:\n" ${SSL_PATH})
message("using crypto library file: \n" ${CRYPTO_PATH} "\n")

add_definitions(-fPIC)
add_definitions(-DSSS_USE_FTR_FILE)
add_definitions(-DSMCOM_T1oI2C)
add_definitions(-DT1oI2C)
add_definitions(-DT1oI2C_UM11225)
add_definitions(-DT1OI2C_RETRY_ON_I2C_FAILED)