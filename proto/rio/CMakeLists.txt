cmake_minimum_required(VERSION 2.6)

project(linux-edlp)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin")

add_definitions(-DSHOW_RESULTS)
add_definitions(-DSHOW_SYMBOLS)

find_package(DynamoRIO 3.1)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

# sysdlp: syscall DLP hooks
add_library(sysdlp SHARED sysdlp.cc)
configure_DynamoRIO_client(sysdlp)
use_DynamoRIO_extension(sysdlp drmgr)
use_DynamoRIO_extension(sysdlp drutil)