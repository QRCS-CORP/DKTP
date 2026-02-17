cmake_minimum_required(VERSION 3.15)

project(DKTP_Complete C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Output dirs
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Download and build QSC
include(FetchContent)
FetchContent_Declare(
  QSC
  GIT_REPOSITORY https://github.com/QRCS-CORP/QSC.git
  GIT_TAG master
)
FetchContent_MakeAvailable(QSC)

# DKTP Static Library
file(GLOB_RECURSE DKTP_SOURCES "Source/DKTP/*.c")
file(GLOB_RECURSE DKTP_HEADERS "Source/DKTP/*.h")

add_library(dktp STATIC ${DKTP_SOURCES} ${DKTP_HEADERS})
target_include_directories(dktp PUBLIC "Source/DKTP")
target_link_libraries(dktp PUBLIC qsc)

# DKTP Listener
file(GLOB_RECURSE DKTP_LISTENER_SOURCES "Source/Listener/*.c")

add_executable(dktp_listener ${DKTP_LISTENER_SOURCES})
target_include_directories(dktp_listener PRIVATE "Source/Listener")
target_link_libraries(dktp_listener PRIVATE dktp)

# DKTP Sender
file(GLOB_RECURSE DKTP_SENDER_SOURCES "Source/Sender/*.c")

add_executable(dktp_sender ${DKTP_SENDER_SOURCES})
target_include_directories(dktp_sender PRIVATE "Source/Sender")
target_link_libraries(dktp_sender PRIVATE dktp)

# Warnings
foreach(target dktp dktp_listener dktp_sender)
  if (MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
endforeach()
