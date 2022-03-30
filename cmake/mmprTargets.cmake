add_library(mmpr::mmpr STATIC IMPORTED)
set_target_properties(mmpr::mmpr PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${_IMPORT_PREFIX}/include"
    INTERFACE_LINK_LIBRARIES "Boost::boost;ZSTD::ZSTD;\$<LINK_ONLY:Boost::filesystem>"
)
