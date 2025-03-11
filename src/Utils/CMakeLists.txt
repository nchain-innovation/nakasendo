
set(Utils_HPP_FILES_PUBLIC # Keep alphabet order
    ${CMAKE_CURRENT_SOURCE_DIR}/conversions.h
    ${CMAKE_CURRENT_SOURCE_DIR}/hashing.h
    ${CMAKE_CURRENT_SOURCE_DIR}/kdf.h
)

set(Utils_CPP_FILES # Keep alphabet order
    ${CMAKE_CURRENT_SOURCE_DIR}/conversions.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/hashing.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/kdf.cc
)

set(Utils_SOURCE_FILES ${Utils_HPP_FILES_PUBLIC} ${Utils_CPP_FILES})
add_library(Utils ${LIBS_BUILD_TYPE} ${Utils_SOURCE_FILES})
target_link_libraries(Utils BigNumbers OpenSSL::Crypto OpenSSL::SSL ${CMAKE_DL_LIBS} ${CMAKE_THREAD_LIBS_INIT})
target_compile_definitions(Utils PRIVATE EXPORT_Utils)
set_property(TARGET Utils PROPERTY FOLDER "core")

#install(FILES ${ECPoint_HPP_FILES_PUBLIC} DESTINATION "include/ECPoint" COMPONENT core)
#install(TARGETS ECPoint DESTINATION "lib" COMPONENT core)


