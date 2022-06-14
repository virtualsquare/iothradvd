cmake_minimum_required(VERSION 3.12)
project(iothradvd
		VERSION 0.0.1
		DESCRIPTION "Router Advertisement Daemon for the Ioth"
		HOMEPAGE_URL "https://github.com/virtualsquare/iothradvd"
		LANGUAGES C)

include(GNUInstallDirs)
include(CheckIncludeFile)
include(CheckSymbolExists)

add_definitions(-D_GNU_SOURCE)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FORTIFY_SOURCE=2 -O2 -pedantic -Wall -Wextra")

set(LIBS_REQUIRED ioth iothconf vdeplug iothaddr)
set(HEADERS_REQUIRED ioth.h iothaddr.h iothconf.h)

foreach(THISLIB IN LISTS LIBS_REQUIRED)
  find_library(LIB${THISLIB}_OK ${THISLIB})
  if(NOT LIB${THISLIB}_OK)
    message(FATAL_ERROR "library lib${THISLIB} not found")
  endif()
endforeach(THISLIB)

foreach(HEADER IN LISTS HEADERS_REQUIRED)
  check_include_file(${HEADER} ${HEADER}_OK)
  if(NOT ${HEADER}_OK)
    message(FATAL_ERROR "header file ${HEADER} not found")
  endif()
endforeach(HEADER)

add_definitions(-D_GNU_SOURCE)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_library(libiothradvd SHARED libiothradvd.c)
target_link_libraries(libiothradvd ioth iothconf vdeplug iothaddr)
set_target_properties(libiothradvd PROPERTIES
		OUTPUT_NAME "iothradvd"
		VERSION ${PROJECT_VERSION}
		SOVERSION ${PROJECT_VERSION_MAJOR})

add_library(libiothradvd-static STATIC libiothradvd.c)
set_target_properties(libiothradvd-static
		PROPERTIES OUTPUT_NAME iothradvd)

configure_file(iothradvd.pc.in iothradvd.pc @ONLY)

install(TARGETS libiothradvd
		LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(TARGETS libiothradvd-static
		ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES iothradvd.h
		DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/iothradvd.pc
		DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

add_executable(iothradvd iothradvd.c utils.c)
target_link_libraries(iothradvd libiothradvd cap)

install(TARGETS iothradvd
		RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# add_subdirectory(man)

add_custom_target(uninstall
  "${CMAKE_COMMAND}" -P "${PROJECT_SOURCE_DIR}/Uninstall.cmake")
