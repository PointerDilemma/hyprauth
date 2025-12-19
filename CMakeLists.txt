cmake_minimum_required(VERSION 3.19)

file(READ "${CMAKE_SOURCE_DIR}/VERSION" VER_RAW)
string(STRIP ${VER_RAW} HYPRAUTH_VERSION)

add_compile_definitions(HYPRAUTH_VERSION="${HYPRAUTH_VERSION}")

project(
  hyprauth
  VERSION ${HYPRAUTH_VERSION}
  DESCRIPTION "C++ authentication module")

#include(CheckIncludeFile)
include(GNUInstallDirs)

set(PREFIX ${CMAKE_INSTALL_PREFIX})
set(INCLUDE ${CMAKE_INSTALL_FULL_INCLUDEDIR})
set(LIBDIR ${CMAKE_INSTALL_FULL_LIBDIR})

find_package(PkgConfig REQUIRED)
pkg_check_modules(
  deps
  REQUIRED
  IMPORTED_TARGET
  hyprutils>=0.11.0
  sdbus-c++>=2.0.0
  hyprwire
)
find_library(PAM_FOUND pam)
if(PAM_FOUND)
  message(STATUS "Found pam")
  set(PAM_LIB ${PAM_FOUND})
else()
  pkg_check_modules(PAM IMPORTED_TARGET pam)
  if(PAM_FOUND)
    set(PAM_LIB PkgConfig::PAM)
  else()
    message(FATAL_ERROR "The required library libpam was not found.")
  endif()
endif()

configure_file(hyprauth.pc.in hyprauth.pc @ONLY)

set(CMAKE_CXX_STANDARD 23)
add_compile_options(
  -Wall
  -Wextra
  -Wpedantic
  -Wno-unused-parameter
  -Wno-unused-value
  -Wno-missing-field-initializers
  -Wno-narrowing
  -Wno-pointer-arith)
set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)

if(CMAKE_BUILD_TYPE MATCHES Debug OR CMAKE_BUILD_TYPE MATCHES DEBUG)
  message(STATUS "Configuring hyprauth in Debug")
  add_compile_definitions(HYPRAUTH_DEBUG)
  set(BUILD_TESTING ON)
else()
  add_compile_options(-O3)
  message(STATUS "Configuring hyprauth in Release")
endif()

add_compile_definitions(HT_HIDDEN=public)

file(GLOB_RECURSE SRCFILES CONFIGURE_DEPENDS "src/*.cpp" "include/*.hpp")
file(GLOB_RECURSE PUBLIC_HEADERS CONFIGURE_DEPENDS "include/*.hpp")

# helper func
function(protocol proto_dir proto_name is_client out_base out_var)
  if(is_client)
    set(mode "--client")
    set(suffix "client")
  else()
    set(mode "")
    set(suffix "server")
  endif()

  set(outdir "${CMAKE_SOURCE_DIR}/src/core/pam/generated")
  set(xml_in "${proto_dir}/${proto_name}.xml")

  set(tmp_cpp "${outdir}/${proto_name}-${suffix}.cpp")
  set(tmp_hpp "${outdir}/${proto_name}-${suffix}.hpp")

  set(out_cpp "${outdir}/${out_base}-${suffix}.cpp")
  set(out_hpp "${outdir}/${out_base}-${suffix}.hpp")

  add_custom_command(
    OUTPUT "${out_cpp}" "${out_hpp}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${outdir}"
    COMMAND "hyprwire-scanner" ${mode} "${xml_in}" "${outdir}"
    DEPENDS "${xml_in}"
    VERBATIM
    COMMENT
      "Generating ${suffix} protocol from ${proto_name}.xml -> ${out_base}-${suffix}.{cpp,hpp}"
  )

  set(${out_var}
      "${out_cpp};${out_hpp}"
      PARENT_SCOPE)
endfunction()
protocol("${CMAKE_SOURCE_DIR}/src/core/pam" "hyprauth-pam-v1" TRUE "hyprauth_pam_v1"
         CLIENT_GEN)
protocol("${CMAKE_SOURCE_DIR}/src/core/pam" "hyprauth-pam-v1" FALSE "hyprauth_pam_v1"
         SERVER_GEN)


add_library(hyprauth SHARED ${SRCFILES} "${CMAKE_SOURCE_DIR}/src/core/pam/generated/hyprauth_pam_v1-client.cpp"
                                        "${CMAKE_SOURCE_DIR}/src/core/pam/generated/hyprauth_pam_v1-server.cpp")
target_include_directories(
  hyprauth
  PUBLIC "./include"
  PRIVATE "./src" "${CMAKE_BINARY_DIR}")
set_target_properties(hyprauth PROPERTIES VERSION ${HYPRAUTH_VERSION} SOVERSION 1)
target_link_libraries(hyprauth ${PAM_LIB} PkgConfig::deps)

# tests
if(BUILD_TESTING)
  message(STATUS "building tests is enabled")

  # GTest
  find_package(GTest CONFIG REQUIRED)
  include(GoogleTest)
  file(GLOB_RECURSE TESTFILES CONFIGURE_DEPENDS "tests/unit/*.cpp")
  add_executable(hyprauth_unit_tests ${TESTFILES})

  target_compile_options(hyprauth_unit_tests PRIVATE --coverage)
  target_link_options(hyprauth_unit_tests PRIVATE --coverage)

  target_include_directories(
    hyprauth_unit_tests
    PUBLIC "./include"
    PRIVATE "./src" "./src/include" "${CMAKE_BINARY_DIR}")
  target_link_libraries(hyprauth_unit_tests PRIVATE hyprauth GTest::gtest_main
                                                       PkgConfig::deps)
  gtest_discover_tests(hyprauth_unit_tests)

  # Add coverage to hyprauth for test builds
  target_compile_options(hyprauth PRIVATE --coverage)
  target_link_options(hyprauth PRIVATE --coverage)

  add_executable(cliauth "tests/cliauth.cpp")
  target_link_libraries(cliauth PRIVATE PkgConfig::deps hyprauth)

  add_executable(cliauth_c "tests/cliauth.c")
  target_link_libraries(cliauth_c PRIVATE PkgConfig::deps hyprauth)

  install(DIRECTORY "include/hyprauth" DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

  install(TARGETS cliauth cliauth_c hyprauth_unit_tests)
else()
  message(STATUS "building tests is disabled")
endif()

# Installation
install(TARGETS hyprauth)
install(DIRECTORY "include/hyprauth" DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES ${CMAKE_BINARY_DIR}/hyprauth.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
