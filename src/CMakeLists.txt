set(HEADER_LIST
        "${MMPR_SOURCE_DIR}/include/mmpr/mmpr.h"
        "${MMPR_SOURCE_DIR}/include/mmpr/PcapNgBlockParser.h"
        "${MMPR_SOURCE_DIR}/include/mmpr/PcapNgBlockOptionParser.h"
        ../include/mmpr/util.h)

# MMPR lib target, will be static or dynamic based on user setting
add_library(mmpr
        ${HEADER_LIST}
        PcapNgReader.cpp
        PcapNgBlockParser.cpp
        PcapNgBlockOptionParser.cpp
        )

target_include_directories(mmpr
        PUBLIC
        ../include
        ${Boost_INCLUDE_DIRS}
        )

target_link_libraries(mmpr
        PRIVATE
        ${Boost_LIBRARIES}
        fmt::fmt
        )

target_compile_features(mmpr PUBLIC cxx_std_11)

# IDEs should put the headers in a nice place
source_group(TREE "${PROJECT_SOURCE_DIR}/include"
        PREFIX "Header Files"
        FILES ${HEADER_LIST}
        )
