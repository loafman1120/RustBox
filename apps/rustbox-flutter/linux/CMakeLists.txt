cmake_minimum_required(VERSION 3.10)

set(PROJECT_NAME "rustbox_flutter")
project(${PROJECT_NAME} LANGUAGES C)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
  set(RUSTBOX_ARCH "arm64")
else()
  set(RUSTBOX_ARCH "x64")
endif()

set(RUSTBOX_LIBRARY
  "${CMAKE_CURRENT_SOURCE_DIR}/../native/linux/${RUSTBOX_ARCH}/librustbox_flutter_bridge.so")

if(NOT EXISTS "${RUSTBOX_LIBRARY}")
  message(FATAL_ERROR "Missing precompiled RustBox library: ${RUSTBOX_LIBRARY}")
endif()

set(rustbox_flutter_bundled_libraries
  "${RUSTBOX_LIBRARY}"
  PARENT_SCOPE
)
