cmake_minimum_required(VERSION 3.10)
project(mod_bw C)

# Find Apache APR and APR-Util
find_package(PkgConfig REQUIRED)
pkg_check_modules(APR      REQUIRED apr-1)
pkg_check_modules(APR_UTIL REQUIRED apr-util-1)

# Find apxs (Apache Extension Tool)
find_program(APXS apxs REQUIRED)
execute_process(
    COMMAND ${APXS} -q includedir
    OUTPUT_VARIABLE APACHE_INCLUDE_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
execute_process(
    COMMAND ${APXS} -q LIBEXECDIR
    OUTPUT_VARIABLE APACHE_MODULES_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

message(STATUS "Apache include dir : ${APACHE_INCLUDE_DIR}")
message(STATUS "Apache modules dir : ${APACHE_MODULES_DIR}")

# Compiler flags
set(CMAKE_C_STANDARD 99)
# -g: DWARF debug symbols (already present by CMake default, made explicit)
# -fno-omit-frame-pointer: keeps frame pointers so gdb backtraces are accurate
#   even at higher optimisation levels (near-zero runtime cost for a module)
add_compile_options(-Wall -Wextra -Wno-unused-parameter -g -fno-omit-frame-pointer)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${APR_INCLUDE_DIRS}
    ${APR_UTIL_INCLUDE_DIRS}
    ${APACHE_INCLUDE_DIR}
)

# Source files
set(SRC_FILES
    src/mod_bw.c
    src/mod_bw_config.c
    src/mod_bw_filter.c
    src/mod_bw_shm.c
    src/mod_bw_util.c
    src/mod_bw_api.c
    src/mod_bw_tokens.c
    src/bw_sha256.c
)

# Build as a position-independent shared module
add_library(mod_bw MODULE ${SRC_FILES})
set_target_properties(mod_bw PROPERTIES
    PREFIX              ""
    OUTPUT_NAME         "mod_bw"
    SUFFIX              ".so"
    C_VISIBILITY_PRESET default
)

target_compile_definitions(mod_bw PRIVATE
    _REENTRANT
)

# -- Optional Linux kernel-assisted egress throttle paths --------------
# Compiled in only when enabled AND the target is Linux with the required
# socket options. On other platforms (or when disabled) the BandWidthThrottleMode
# directive transparently falls back to the portable "sleep" method.
option(BW_ENABLE_KERNEL_PACING "Compile the SO_MAX_PACING_RATE 'pacing' mode"   ON)
option(BW_ENABLE_TC_MARKING    "Compile the DSCP/tc 'tc' mode"                  ON)
option(BW_ENABLE_RCV_CLAMP     "Compile the TCP receive-window 'clamp' ingress" ON)
option(BW_ENABLE_SO_MARK       "Compile the SO_MARK 'mark' mode (both directions)" ON)
if(BW_ENABLE_KERNEL_PACING)
    target_compile_definitions(mod_bw PRIVATE BW_WANT_PACING)
endif()
if(BW_ENABLE_TC_MARKING)
    target_compile_definitions(mod_bw PRIVATE BW_WANT_TC)
endif()
if(BW_ENABLE_RCV_CLAMP)
    target_compile_definitions(mod_bw PRIVATE BW_WANT_CLAMP)
endif()
if(BW_ENABLE_SO_MARK)
    target_compile_definitions(mod_bw PRIVATE BW_WANT_MARK)
endif()
message(STATUS "mod_bw kernel pacing : ${BW_ENABLE_KERNEL_PACING}")
message(STATUS "mod_bw tc marking    : ${BW_ENABLE_TC_MARKING}")
message(STATUS "mod_bw rcv clamp     : ${BW_ENABLE_RCV_CLAMP}")
message(STATUS "mod_bw so_mark       : ${BW_ENABLE_SO_MARK}")

target_link_libraries(mod_bw
    ${APR_LIBRARIES}
    ${APR_UTIL_LIBRARIES}
)

# Installation
install(TARGETS mod_bw
    LIBRARY DESTINATION ${APACHE_MODULES_DIR}
)

# Convenience target: install via apxs
add_custom_target(apxs_install
    COMMAND ${APXS} -i -a -n bw $<TARGET_FILE:mod_bw>
    DEPENDS mod_bw
    COMMENT "Installing mod_bw via apxs"
)

# Show build summary
message(STATUS "mod_bw sources: ${SRC_FILES}")
