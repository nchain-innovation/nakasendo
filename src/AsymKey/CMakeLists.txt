
set(ASymKey_HPP_FILES_PUBLIC # Keep alphabet order
    ${CMAKE_CURRENT_SOURCE_DIR}/AsymKey.h
)

set(ASymKey_CPP_FILES # Keep alphabet order
    ${CMAKE_CURRENT_SOURCE_DIR}/AsymKey.cc
)

set(ASymKey_SOURCE_FILES ${ASymKey_HPP_FILES_PUBLIC} ${ASymKey_CPP_FILES})
add_library(ASymKey ${LIBS_BUILD_TYPE} ${ASymKey_SOURCE_FILES})
target_link_libraries(ASymKey BigNumbers OpenSSL::Crypto OpenSSL::SSL ${CMAKE_DL_LIBS} ${CMAKE_THREAD_LIBS_INIT})
target_compile_definitions(ASymKey PRIVATE EXPORT_ASymKey)
set_property(TARGET ASymKey PROPERTY FOLDER "core")

#install(FILES ${ECPoint_HPP_FILES_PUBLIC} DESTINATION "include/ECPoint" COMPONENT core)
#install(TARGETS ECPoint DESTINATION "lib" COMPONENT core)


