cmake_minimum_required(VERSION 3.2)
project(md4sum)

set(SOURCES
  md4sum.c
)

add_executable (md4sum ${SOURCES})
set_property(TARGET md4sum PROPERTY CXX_STANDARD 98)
install(TARGETS md4sum DESTINATION bin)
