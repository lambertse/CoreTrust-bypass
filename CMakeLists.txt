cmake_minimum_required(VERSION 3.16)

project(ct_bypass LANGUAGES CXX)

if(NOT APPLE)
  message(FATAL_ERROR "${PROJECT_NAME} requires an Apple platform (Security.framework)")
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_library(COREFOUNDATION_FRAMEWORK CoreFoundation REQUIRED)
find_library(SECURITY_FRAMEWORK Security REQUIRED)

add_library(${PROJECT_NAME} SHARED
  src/ad_hoc_signer.cpp
  src/template/template.cpp
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
)
