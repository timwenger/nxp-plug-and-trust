project(ex_ecc)
message("configuring project:\n" ${PROJECT_NAME} "\n")

# add an executable target named ex_ecc, built with all the source files in the 3 trailing arguments
add_executable(${PROJECT_NAME} ${SIMW_SE_SOURCES} ${SIMW_SE_AUTH_SOURCES} ../sss/ex/ecc/ex_sss_ecc.c)

target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES})

# consider all the include files defined in the SIM_INC_DIR list of directories
target_include_directories( ${PROJECT_NAME} PUBLIC ${SIMW_INC_DIR} )
