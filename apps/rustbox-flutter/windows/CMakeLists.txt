cmake_minimum_required(VERSION 3.14)

set(PROJECT_NAME "rustbox_flutter")
project(${PROJECT_NAME} LANGUAGES C)

if(CMAKE_GENERATOR_PLATFORM STREQUAL "ARM64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
  set(RUSTBOX_ARCH "arm64")
else()
  set(RUSTBOX_ARCH "x64")
endif()

set(RUSTBOX_LIBRARY
  "${CMAKE_CURRENT_SOURCE_DIR}/../native/windows/${RUSTBOX_ARCH}/rustbox_flutter_bridge.dll")
set(RUSTBOX_WINTUN
  "${CMAKE_CURRENT_SOURCE_DIR}/../native/windows/${RUSTBOX_ARCH}/wintun.dll")
set(RUSTBOX_WATCHDOG
  "${CMAKE_CURRENT_SOURCE_DIR}/../native/windows/${RUSTBOX_ARCH}/rustbox-watchdog.exe")

if(NOT EXISTS "${RUSTBOX_LIBRARY}")
  message(FATAL_ERROR "Missing precompiled RustBox library: ${RUSTBOX_LIBRARY}")
endif()
if(NOT EXISTS "${RUSTBOX_WINTUN}")
  message(FATAL_ERROR "Missing bundled Wintun runtime: ${RUSTBOX_WINTUN}. Run scripts/build/flutter-prebuilt.ps1 -Platform windows")
endif()
if(NOT EXISTS "${RUSTBOX_WATCHDOG}")
  message(FATAL_ERROR "Missing RustBox recovery watchdog: ${RUSTBOX_WATCHDOG}. Run scripts/build/flutter-prebuilt.ps1 -Platform windows")
endif()

set(rustbox_flutter_bundled_libraries
  "${RUSTBOX_LIBRARY}"
  "${RUSTBOX_WINTUN}"
  "${RUSTBOX_WATCHDOG}"
  PARENT_SCOPE
)
