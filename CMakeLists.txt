cmake_minimum_required(VERSION 3.16)
project(PacketAnalyzer VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CORE_SOURCES
    src/connection_tracker.cpp
    src/dpi_engine.cpp
    src/dpi_processor.cpp
    src/fast_path.cpp
    src/load_balancer.cpp
    src/packet_parser.cpp
    src/pcap_reader.cpp
    src/rule_manager.cpp
    src/sni_extractor.cpp
    src/types.cpp
)

include_directories(${CMAKE_SOURCE_DIR}/include)

find_package(Threads REQUIRED)

add_executable(dpi_api    src/main_json.cpp    ${CORE_SOURCES})
add_executable(dpi_simple src/main_simple.cpp  ${CORE_SOURCES})
add_executable(dpi_engine src/main_dpi.cpp     ${CORE_SOURCES})

target_link_libraries(dpi_api    PRIVATE Threads::Threads)
target_link_libraries(dpi_simple PRIVATE Threads::Threads)
target_link_libraries(dpi_engine PRIVATE Threads::Threads)

if(APPLE)
endif()
