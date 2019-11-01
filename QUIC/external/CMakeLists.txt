include(ExternalProject)

find_package(OpenSSL)

# Use picoquic for testing against
externalproject_add(picoquic
        UPDATE_COMMAND ""
        GIT_REPOSITORY https://github.com/private-octopus/picoquic.git
        GIT_SHALLOW 1
        # GIT_TAG draft-21
        BUILD_IN_SOURCE 1
        CMAKE_ARGS
        -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
        -DOPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR}
        -DPTLS_INCLUDE_DIR=${PROJECT_SOURCE_DIR}/lib/deps/picotls/include
        -DPTLS_CORE_LIBRARY=${CMAKE_BINARY_DIR}/lib/deps/picotls/libpicotls-core.a
        -DPTLS_MINICRYPTO_LIBRARY=${CMAKE_BINARY_DIR}/lib/deps/picotls/libpicotls-minicrypto.a
        -DPTLS_OPENSSL_LIBRARY=${CMAKE_BINARY_DIR}/lib/deps/picotls/libpicotls-openssl.a
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        -DCMAKE_C_FLAGS="-D_DEBUG"
        INSTALL_COMMAND ""
        EXCLUDE_FROM_ALL 1
        )

add_custom_target(ext-all DEPENDS
        picoquic
        )