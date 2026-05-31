cmake_minimum_required(VERSION 3.15)
project(kwatch VERSION 1.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror -g -O2")

option(KWATCH_BUILD_TUI "Build the optional ncurses TUI command" OFF)
option(KWATCH_ENABLE_EXPERIMENTAL "Enable experimental SYN/auto-block features" OFF)
option(KWATCH_BUILD_FUZZ "Build optional fuzz targets" OFF)

if(KWATCH_BUILD_TUI AND NOT KWATCH_ENABLE_EXPERIMENTAL)
    message(FATAL_ERROR "KWATCH_BUILD_TUI currently requires KWATCH_ENABLE_EXPERIMENTAL=ON.")
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)
pkg_check_modules(LIBELF REQUIRED libelf)
pkg_check_modules(ZLIB REQUIRED zlib)

# R2.3: discover bpftool via pkg-config -> which -> distro-versioned fallback.
execute_process(
    COMMAND pkg-config --variable=bpftool libbpf
    OUTPUT_VARIABLE BPFTOOL_PATH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(NOT BPFTOOL_PATH OR NOT EXISTS "${BPFTOOL_PATH}")
    find_program(BPFTOOL_PATH bpftool)
endif()
if(NOT BPFTOOL_PATH OR NOT EXISTS "${BPFTOOL_PATH}")
    # Some distros (e.g. Ubuntu) ship bpftool only under linux-tools-<ver>/.
    file(GLOB BPFTOOL_FALLBACK "/usr/lib/linux-tools/*/bpftool")
    if(BPFTOOL_FALLBACK)
        list(GET BPFTOOL_FALLBACK 0 BPFTOOL_PATH)
    endif()
endif()
if(NOT BPFTOOL_PATH OR NOT EXISTS "${BPFTOOL_PATH}")
    message(FATAL_ERROR "bpftool not found. Install linux-tools-common, bpftool, or set PATH.")
endif()
message(STATUS "Using bpftool: ${BPFTOOL_PATH}")

# Find clang for bpf compilation
find_program(CLANG_EXE clang)
if(NOT CLANG_EXE)
    message(FATAL_ERROR "clang not found. Please install clang.")
endif()

set(GENERATED_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include/generated)
file(MAKE_DIRECTORY ${GENERATED_DIR})

set(VMLINUX_H ${GENERATED_DIR}/vmlinux.h)
add_custom_command(
    OUTPUT ${VMLINUX_H}
    COMMAND ${BPFTOOL_PATH} btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX_H}
    COMMENT "Generating vmlinux.h"
    VERBATIM
)

set(BPF_C ${CMAKE_CURRENT_SOURCE_DIR}/bpf/kwatch.bpf.c)
set(BPF_SHARED ${CMAKE_CURRENT_SOURCE_DIR}/bpf/kwatch_shared.h)
set(BPF_O ${GENERATED_DIR}/kwatch.bpf.o)
add_custom_command(
    OUTPUT ${BPF_O}
    COMMAND ${CLANG_EXE} -g -O2 -target bpf -D__TARGET_ARCH_x86 -mcpu=v3 -I${GENERATED_DIR} -I/usr/include/x86_64-linux-gnu -c ${BPF_C} -o ${BPF_O}
    DEPENDS ${BPF_C} ${BPF_SHARED} ${VMLINUX_H}
    COMMENT "Compiling BPF program"
    VERBATIM
)

set(SKEL_H ${GENERATED_DIR}/kwatch.skel.h)
add_custom_command(
    OUTPUT ${SKEL_H}
    COMMAND ${BPFTOOL_PATH} gen skeleton ${BPF_O} > ${SKEL_H}
    DEPENDS ${BPF_O}
    COMMENT "Generating BPF skeleton"
    VERBATIM
)

add_custom_target(bpf-obj DEPENDS ${SKEL_H})

# Get Git SHA for version string
execute_process(
    COMMAND git rev-parse --short HEAD
    OUTPUT_VARIABLE GIT_SHA
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
add_definitions(-DGIT_SHA="${GIT_SHA}")
add_definitions(-DPROJECT_VERSION="${PROJECT_VERSION}")

file(GLOB_RECURSE SOURCES "src/*.cpp")
if(NOT KWATCH_BUILD_TUI)
    list(FILTER SOURCES EXCLUDE REGEX "src/cli/commands/top.cpp$")
    list(FILTER SOURCES EXCLUDE REGEX "src/tui/.*")
else()
    add_definitions(-DKWATCH_WITH_TUI=1)
endif()
if(KWATCH_ENABLE_EXPERIMENTAL)
    add_definitions(-DKWATCH_WITH_EXPERIMENTAL=1)
else()
    list(FILTER SOURCES EXCLUDE REGEX "src/core/flow_tracker.cpp$")
    list(FILTER SOURCES EXCLUDE REGEX "src/demo/syn_flood.cpp$")
endif()

# Exclude main from tests
list(FILTER SOURCES EXCLUDE REGEX "src/cli/main.cpp")

add_executable(kwatch ${SOURCES} src/cli/main.cpp)
add_dependencies(kwatch bpf-obj)
target_include_directories(kwatch SYSTEM PRIVATE ${GENERATED_DIR})
target_link_options(kwatch PRIVATE ${LIBBPF_LDFLAGS} ${LIBELF_LDFLAGS} ${ZLIB_LDFLAGS})
target_link_directories(kwatch PRIVATE ${LIBBPF_LIBRARY_DIRS} ${LIBELF_LIBRARY_DIRS} ${ZLIB_LIBRARY_DIRS})
target_link_libraries(kwatch PRIVATE ${LIBBPF_LIBRARIES} ${LIBELF_LIBRARIES} ${ZLIB_LIBRARIES})
if(KWATCH_BUILD_TUI)
    target_link_libraries(kwatch PRIVATE ncurses tinfo)
endif()

file(GLOB_RECURSE TEST_SOURCES "tests/unit/*.cpp")
if(NOT KWATCH_ENABLE_EXPERIMENTAL)
    list(FILTER TEST_SOURCES EXCLUDE REGEX "tests/unit/flow_tracker_test.cpp$")
endif()
add_executable(kwatch_tests ${TEST_SOURCES} ${SOURCES})
add_dependencies(kwatch_tests bpf-obj)
target_include_directories(kwatch_tests SYSTEM PRIVATE ${GENERATED_DIR})
target_include_directories(kwatch_tests PRIVATE tests/vendored)
target_link_options(kwatch_tests PRIVATE ${LIBBPF_LDFLAGS} ${LIBELF_LDFLAGS} ${ZLIB_LDFLAGS})
target_link_directories(kwatch_tests PRIVATE ${LIBBPF_LIBRARY_DIRS} ${LIBELF_LIBRARY_DIRS} ${ZLIB_LIBRARY_DIRS})
target_link_libraries(kwatch_tests PRIVATE ${LIBBPF_LIBRARIES} ${LIBELF_LIBRARIES} ${ZLIB_LIBRARIES})
if(KWATCH_BUILD_TUI)
    target_link_libraries(kwatch_tests PRIVATE ncurses tinfo)
endif()

# Fuzzing target (optional, off by default for the portfolio build/test surface)
if(KWATCH_BUILD_FUZZ)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "KWATCH_BUILD_FUZZ requires Clang.")
    endif()
    add_executable(kwatch_fuzz_parser
        tests/fuzz/ringbuf_event_parser_fuzz.cpp
        src/util/ipv4.cpp
    )
    target_compile_options(kwatch_fuzz_parser PRIVATE -fsanitize=fuzzer)
    target_link_options(kwatch_fuzz_parser PRIVATE -fsanitize=fuzzer)
    target_include_directories(kwatch_fuzz_parser PRIVATE bpf)
endif()
