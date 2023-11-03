project (ex_ecc)

add_executable(${PROJECT_NAME} ${SIMW_SE_SOURCES} ${SIMW_SE_AUTH_SOURCES} ../sss/ex/ecc/ex_sss_ecc.c)

target_link_libraries(${PROJECT_NAME} ssl crypto)

target_include_directories(
    ${PROJECT_NAME}
    PUBLIC
    ../
    ${SIMW_INC_DIR}
    )
