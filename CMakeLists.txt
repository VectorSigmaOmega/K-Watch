cmake_minimum_required(VERSION 3.15)
project(kwatch CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror -g -O2")

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)
pkg_check_modules(LIBELF REQUIRED libelf)
pkg_check_modules(ZLIB REQUIRED zlib)

# Find bpftool (prioritize actual binary over WSL-failing wrapper)
file(GLOB BPFTOOL_FALLBACK "/usr/lib/linux-tools/*/bpftool")
if(BPFTOOL_FALLBACK)
    list(GET BPFTOOL_FALLBACK 0 BPFTOOL_PATH)
else()
    execute_process(
        COMMAND pkg-config --variable=bpftool libbpf
        OUTPUT_VARIABLE BPFTOOL_PATH
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(NOT BPFTOOL_PATH OR NOT EXISTS "${BPFTOOL_PATH}")
        find_program(BPFTOOL_PATH bpftool)
    endif()
endif()
if(NOT BPFTOOL_PATH OR NOT EXISTS "${BPFTOOL_PATH}")
    message(FATAL_ERROR "bpftool not found. Please install linux-tools-common or bpftool.")
endif()

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
set(BPF_O ${GENERATED_DIR}/kwatch.bpf.o)
add_custom_command(
    OUTPUT ${BPF_O}
    COMMAND ${CLANG_EXE} -g -O2 -target bpf -D__TARGET_ARCH_x86 -mcpu=v3 -I${GENERATED_DIR} -c ${BPF_C} -o ${BPF_O}
    DEPENDS ${BPF_C} ${VMLINUX_H}
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

file(GLOB_RECURSE SOURCES "src/*.cpp")
# Exclude main from tests
list(FILTER SOURCES EXCLUDE REGEX "src/cli/main.cpp")

add_executable(kwatch ${SOURCES} src/cli/main.cpp)
add_dependencies(kwatch bpf-obj)
target_include_directories(kwatch PRIVATE ${GENERATED_DIR})
target_link_options(kwatch PRIVATE ${LIBBPF_LDFLAGS} ${LIBELF_LDFLAGS} ${ZLIB_LDFLAGS})
target_link_directories(kwatch PRIVATE ${LIBBPF_LIBRARY_DIRS} ${LIBELF_LIBRARY_DIRS} ${ZLIB_LIBRARY_DIRS})
target_link_libraries(kwatch PRIVATE ${LIBBPF_LIBRARIES} ${LIBELF_LIBRARIES} ${ZLIB_LIBRARIES} ncurses tinfo)

file(GLOB_RECURSE TEST_SOURCES "tests/unit/*.cpp")
add_executable(kwatch_tests ${TEST_SOURCES} ${SOURCES})
add_dependencies(kwatch_tests bpf-obj)
target_include_directories(kwatch_tests PRIVATE ${GENERATED_DIR} tests/vendored)
target_link_options(kwatch_tests PRIVATE ${LIBBPF_LDFLAGS} ${LIBELF_LDFLAGS} ${ZLIB_LDFLAGS})
target_link_directories(kwatch_tests PRIVATE ${LIBBPF_LIBRARY_DIRS} ${LIBELF_LIBRARY_DIRS} ${ZLIB_LIBRARY_DIRS})
target_link_libraries(kwatch_tests PRIVATE ${LIBBPF_LIBRARIES} ${LIBELF_LIBRARIES} ${ZLIB_LIBRARIES} ncurses tinfo)

# Fuzzing target (optional, enabled if using clang and -fsanitize=fuzzer)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_executable(kwatch_fuzz_parser tests/fuzz/ringbuf_event_parser_fuzz.cpp)
    target_compile_options(kwatch_fuzz_parser PRIVATE -fsanitize=fuzzer)
    target_link_options(kwatch_fuzz_parser PRIVATE -fsanitize=fuzzer)
    target_include_directories(kwatch_fuzz_parser PRIVATE bpf)
endif()