unset(CMAKE_C_FLAGS)
unset(CMAKE_C_CLANG_TIDY)
unset(CMAKE_C_INCLUDE_WHAT_YOU_USE)
unset(CMAKE_C_CPPCHECK)

unset(CMAKE_CXX_FLAGS)
unset(CMAKE_CXX_CLANG_TIDY)
unset(CMAKE_CXX_INCLUDE_WHAT_YOU_USE)
unset(CMAKE_CXX_CPPCHECK)

set(CMAKE_POLICY_DEFAULT_CMP0048 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0042 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0054 NEW)

add_subdirectory(picotls)


set(DLEVEL "WRN")


set(PTLS_CORE_LIBRARY
        ${CMAKE_CURRENT_BINARY_DIR}/picotls/libpicotls-core.a
        )

set(PTLS_MINICRYPTO_LIBRARY
        ${CMAKE_CURRENT_BINARY_DIR}/picotls/libpicotls-minicrypto.a
        )

set(PTLS_OPENSSL_LIBRARY
        ${CMAKE_CURRENT_BINARY_DIR}/picotls/libpicotls-openssl.a
        )

add_subdirectory(picoquic)