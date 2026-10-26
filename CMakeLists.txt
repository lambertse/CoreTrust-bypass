cmake_minimum_required(VERSION 3.16)

project(ct_bypass LANGUAGES CXX)

if(NOT APPLE)
  message(FATAL_ERROR "${PROJECT_NAME} requires an Apple platform (Security.framework)")
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_library(COREFOUNDATION_FRAMEWORK CoreFoundation REQUIRED)
find_library(SECURITY_FRAMEWORK Security REQUIRED)

# libcrypto (EVP digests): prefer a local OpenSSL, otherwise build LibreSSL.
option(CT_BYPASS_FETCH_LIBCRYPTO "Build LibreSSL if no local OpenSSL is found" ON)

# Apple's SDK ships no OpenSSL headers; point FindOpenSSL at Homebrew's.
if(NOT OPENSSL_ROOT_DIR AND NOT DEFINED ENV{OPENSSL_ROOT_DIR})
  find_program(BREW_EXECUTABLE brew)
  if(BREW_EXECUTABLE)
    execute_process(
      COMMAND ${BREW_EXECUTABLE} --prefix openssl@3
      OUTPUT_VARIABLE BREW_OPENSSL_PREFIX
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET
      RESULT_VARIABLE BREW_OPENSSL_RESULT
    )
    if(BREW_OPENSSL_RESULT EQUAL 0 AND IS_DIRECTORY "${BREW_OPENSSL_PREFIX}")
      set(OPENSSL_ROOT_DIR "${BREW_OPENSSL_PREFIX}")
    endif()
  endif()
endif()

find_package(OpenSSL COMPONENTS Crypto)

if(NOT TARGET OpenSSL::Crypto)
  if(NOT CT_BYPASS_FETCH_LIBCRYPTO)
    message(FATAL_ERROR "libcrypto not found; set OPENSSL_ROOT_DIR or enable CT_BYPASS_FETCH_LIBCRYPTO")
  endif()
  message(STATUS "Local OpenSSL not found, fetching LibreSSL libcrypto")

  if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
  endif()

  include(FetchContent)

  FetchContent_Declare(
    libressl
    URL https://cdn.openbsd.org/pub/OpenBSD/LibreSSL/libressl-4.0.0.tar.gz
    URL_HASH SHA256=4d841955f0acc3dfc71d0e3dd35f283af461222350e26843fea9731c0246a1e4
  )

  # Static, position-independent libcrypto linked into our shared library.
  set(BUILD_SHARED_LIBS OFF)
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
  set(LIBRESSL_APPS OFF CACHE BOOL "" FORCE)
  set(LIBRESSL_TESTS OFF CACHE BOOL "" FORCE)
  set(LIBRESSL_SKIP_INSTALL ON CACHE BOOL "" FORCE)

  FetchContent_MakeAvailable(libressl)
  # Only libcrypto is needed; skip libssl/libtls unless something links them.
  set_property(DIRECTORY ${libressl_SOURCE_DIR} PROPERTY EXCLUDE_FROM_ALL ON)

  add_library(OpenSSL::Crypto ALIAS crypto)
endif()

add_library(${PROJECT_NAME} SHARED
  src/ad_hoc_signer.cpp
  src/coretrust_bypass.cpp
  src/template/template.cpp
  src/macho/macho.cpp
  src/macho/cs_blob.cpp
  src/macho/digest.cpp
  src/utils.cpp
)

target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_17)
set_target_properties(${PROJECT_NAME} PROPERTIES
  CXX_EXTENSIONS OFF
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN ON
)

target_include_directories(${PROJECT_NAME}
  PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Wpedantic)

target_link_libraries(${PROJECT_NAME}
  PUBLIC  ${COREFOUNDATION_FRAMEWORK}
  PRIVATE ${SECURITY_FRAMEWORK}
          OpenSSL::Crypto
)

option(CT_BYPASS_BUILD_TESTS "Build the unit tests" ON)
if(CT_BYPASS_BUILD_TESTS)
  enable_testing()
  add_subdirectory(test)
endif()
