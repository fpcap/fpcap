add_library(fpcap::fpcap STATIC IMPORTED)

if(FPCAP_USE_ZSTD)
    set_target_properties(fpcap::fpcap PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${_IMPORT_PREFIX}/include"
        INTERFACE_LINK_LIBRARIES "ZSTD::ZSTD"
    )
else()
    set_target_properties(fpcap::fpcap PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${_IMPORT_PREFIX}/include"
    )
endif()
