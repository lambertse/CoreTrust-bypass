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


