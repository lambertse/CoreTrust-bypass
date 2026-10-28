cmake_minimum_required(VERSION 3.16)

include(CTest)
option(CT_BYPASS_USE_SYSTEM_GTEST "Use an installed GoogleTest" OFF)

if(CT_BYPASS_USE_SYSTEM_GTEST)
    find_package(GTest CONFIG REQUIRED)
else()
    if(POLICY CMP0135)
        cmake_policy(SET CMP0135 NEW)
    endif()

    include(FetchContent)

    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
    )

    set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)

    FetchContent_MakeAvailable(googletest)
endif()

include(GoogleTest)

function(add_component_test TEST_NAME)
    add_executable(${TEST_NAME} ${ARGN})

    target_compile_features(${TEST_NAME}
        PRIVATE cxx_std_17
    )

    set_target_properties(${TEST_NAME}
        PROPERTIES
            CXX_EXTENSIONS OFF
    )

    target_include_directories(${TEST_NAME}
        PRIVATE
            ${PROJECT_SOURCE_DIR}/include
            ${PROJECT_SOURCE_DIR}/src
    )

    target_compile_options(${TEST_NAME}
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
    )

    target_link_libraries(${TEST_NAME}
        PRIVATE
            GTest::gtest_main
            ${PROJECT_NAME}
    )

    gtest_discover_tests(${TEST_NAME})
endfunction()

#
# Mach-O tests
#
add_component_test(
    macho_test
    macho/macho_test.cpp
    ${PROJECT_SOURCE_DIR}/src/macho/macho.cpp
)

target_compile_definitions(
    macho_test
    PRIVATE
        MACHO_SAMPLE_PATH="${CMAKE_CURRENT_SOURCE_DIR}/macho_sample"
)



#
# Code signature tests
#
add_component_test(
    cs_blob_test
    macho/cs_blob_test.cpp
    ${PROJECT_SOURCE_DIR}/src/macho/cs_blob.cpp
    ${PROJECT_SOURCE_DIR}/src/macho/digest.cpp
)

target_link_libraries(
    cs_blob_test
    PRIVATE
        OpenSSL::Crypto
)

#
# Mach-O helper tests
#
add_component_test(
    digest_test
    macho/digest_test.cpp
    ${PROJECT_SOURCE_DIR}/src/macho/digest.cpp
)

target_link_libraries(
    digest_test
    PRIVATE
        OpenSSL::Crypto
)

add_component_test(
    macho_utils_test
    macho/utils_test.cpp
)

#
# Template tests
#
add_component_test(
    template_test
    template/template_test.cpp
    ${PROJECT_SOURCE_DIR}/src/template/template.cpp
    ${PROJECT_SOURCE_DIR}/src/macho/cs_blob.cpp
    ${PROJECT_SOURCE_DIR}/src/macho/digest.cpp
)

target_link_libraries(
    template_test
    PRIVATE
        OpenSSL::Crypto
)

#
# CoreFoundation helper tests
#
add_component_test(
    cf_ptr_test
    cf_ptr_test.cpp
)

add_component_test(
    utils_test
    utils_test.cpp
    ${PROJECT_SOURCE_DIR}/src/utils.cpp
)

#
# Ad-hoc signer tests
#
find_program(CODESIGN_EXECUTABLE codesign REQUIRED)

# A normally signed executable for the tests to re-sign, with a known identifier
add_executable(ad_hoc_signer_fixture ad_hoc_signer_fixture.cpp)
add_custom_command(
    TARGET ad_hoc_signer_fixture
    POST_BUILD
    COMMAND ${CODESIGN_EXECUTABLE} --force --sign -
            --identifier com.ct-bypass.ad-hoc-signer-fixture
            $<TARGET_FILE:ad_hoc_signer_fixture>
)

add_component_test(
    ad_hoc_signer_test
    ad_hoc_signer_test.cpp
)

add_dependencies(ad_hoc_signer_test ad_hoc_signer_fixture)

target_link_libraries(
    ad_hoc_signer_test
    PRIVATE
        ${SECURITY_FRAMEWORK}
)

target_compile_definitions(
    ad_hoc_signer_test
    PRIVATE
        AD_HOC_SIGNER_FIXTURE_PATH="$<TARGET_FILE:ad_hoc_signer_fixture>"
)

#
# CoreTrust bypass tests
#
add_component_test(
    coretrust_bypass_test
    coretrust_bypass_test.cpp
    ${PROJECT_SOURCE_DIR}/src/coretrust_bypass.cpp
    ${PROJECT_SOURCE_DIR}/src/log.cpp
    ${PROJECT_SOURCE_DIR}/src/macho/cs_blob.cpp
    ${PROJECT_SOURCE_DIR}/src/macho/digest.cpp
    ${PROJECT_SOURCE_DIR}/src/macho/macho.cpp
    ${PROJECT_SOURCE_DIR}/src/template/template.cpp
    ${PROJECT_SOURCE_DIR}/src/utils.cpp
)

# coretrust_bypass_test.cpp includes test/macho/cd_builders.h
target_include_directories(
    coretrust_bypass_test
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(
    coretrust_bypass_test
    PRIVATE
        OpenSSL::Crypto
        ${COREFOUNDATION_FRAMEWORK}
)

add_dependencies(coretrust_bypass_test ad_hoc_signer_fixture)

target_compile_definitions(
    coretrust_bypass_test
    PRIVATE
        AD_HOC_SIGNER_FIXTURE_PATH="$<TARGET_FILE:ad_hoc_signer_fixture>"
        MACHO_SAMPLE_PATH="${CMAKE_CURRENT_SOURCE_DIR}/macho_sample"
)
