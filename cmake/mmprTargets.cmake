add_library(mmpr::mmpr STATIC IMPORTED)

if(MMPR_USE_ZSTD)
    set_target_properties(mmpr::mmpr PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${_IMPORT_PREFIX}/include"
        INTERFACE_LINK_LIBRARIES "ZSTD::ZSTD"
    )
else()
    set_target_properties(mmpr::mmpr PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${_IMPORT_PREFIX}/include"
    )
endif()
