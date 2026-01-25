cmake_minimum_required(VERSION 3.16)
project(wirefile VERSION 0.1.0 DESCRIPTION "Read and write pcap and pcapng capture files" LANGUAGES C)

option(WIREFILE_BUILD_TESTS "Build tests" OFF)
option(WIREFILE_BUILD_EXAMPLES "Build examples" OFF)
option(WIREFILE_BUILD_FUZZ "Build libFuzzer targets" OFF)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

add_library(wirefile
    src/options.c
    src/read_pcap.c
    src/read_pcapng.c
    src/reader.c
    src/timestamp.c
    src/util.c
    src/write_formats.c
    src/writer.c)
add_library(wirefile::wirefile ALIAS wirefile)
target_include_directories(wirefile PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
set_target_properties(wirefile PROPERTIES
    C_STANDARD 11
    C_VISIBILITY_PRESET hidden
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})

set(PC_CFLAGS "")
if(BUILD_SHARED_LIBS)
    target_compile_definitions(wirefile PRIVATE PCW_BUILD_SHARED INTERFACE PCW_SHARED)
    set(PC_CFLAGS "-DPCW_SHARED")
endif()

install(TARGETS wirefile EXPORT wirefileTargets)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT wirefileTargets
    NAMESPACE wirefile::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/wirefile)

configure_package_config_file(cmake/wirefileConfig.cmake.in
    ${PROJECT_BINARY_DIR}/wirefileConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/wirefile)
write_basic_package_version_file(${PROJECT_BINARY_DIR}/wirefileConfigVersion.cmake
    COMPATIBILITY SameMajorVersion)
install(FILES
    ${PROJECT_BINARY_DIR}/wirefileConfig.cmake
    ${PROJECT_BINARY_DIR}/wirefileConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/wirefile)

configure_file(wirefile.pc.in ${PROJECT_BINARY_DIR}/wirefile.pc @ONLY)
install(FILES ${PROJECT_BINARY_DIR}/wirefile.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

if(WIREFILE_BUILD_TESTS)
    enable_testing()
    add_executable(test_wirefile tests/test_wirefile.c)
    target_link_libraries(test_wirefile PRIVATE wirefile)
    add_test(NAME wirefile COMMAND test_wirefile)
    add_executable(test_corpus tests/test_corpus.c)
    target_link_libraries(test_corpus PRIVATE wirefile)
    add_test(NAME corpus COMMAND test_corpus ${PROJECT_SOURCE_DIR}/tests/data)
    add_library(wirefile_header_check OBJECT tests/header_check.c)
    target_include_directories(wirefile_header_check PRIVATE include)
endif()

if(WIREFILE_BUILD_EXAMPLES)
    foreach(example basic pcwdump pcwcopy)
        add_executable(${example} examples/${example}.c)
        target_link_libraries(${example} PRIVATE wirefile)
    endforeach()
endif()

if(WIREFILE_BUILD_FUZZ)
    add_executable(fuzz_split fuzz/fuzz_split.c)
    target_link_libraries(fuzz_split PRIVATE wirefile)
    target_link_options(fuzz_split PRIVATE -fsanitize=fuzzer)
endif()
