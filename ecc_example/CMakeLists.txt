project(ex_ecc)
message("configuring project:\n" ${PROJECT_NAME} "\n")

# add an executable target named ex_ecc, built with all the source files in the 3 trailing arguments
add_executable(${PROJECT_NAME} ${SIMW_SE_SOURCES} ${SIMW_SE_AUTH_SOURCES} ../sss/ex/ecc/ex_sss_ecc.c)

# link the ex_ecc executable with the dependent openssl libraries
target_link_libraries(${PROJECT_NAME} ssl crypto)
# these commands are only used for printing out the library locations
find_library(SSL_PATH ssl)
find_library(CRYPTO_PATH crypto)
message("using ssl library file:\n" ${SSL_PATH})
message("using crypto library file: \n" ${CRYPTO_PATH} "\n")

# take all the directries defined in SIM_INC_DIR and include them with the ex_ecc executable
target_include_directories( ${PROJECT_NAME} PUBLIC ${SIMW_INC_DIR} )
