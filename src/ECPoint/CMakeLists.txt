
set(ECPoint_HPP_FILES_PUBLIC # Keep alphabet order
    ${CMAKE_CURRENT_SOURCE_DIR}/ECPoint.h
)

set(ECPoint_HPP_FILES ${ECPoint_HPP_FILES_PUBLIC} ${ECPoint_HPP_FILES_PRIVATE})

set(ECPoint_CPP_FILES # Keep alphabet order
    ${CMAKE_CURRENT_SOURCE_DIR}/ECPoint.cpp
)

set(ECPoint_SOURCE_FILES ${ECPoint_HPP_FILES} ${ECPoint_CPP_FILES})
add_library(ECPoint ${LIBS_BUILD_TYPE} ${ECPoint_SOURCE_FILES})
target_link_libraries(ECPoint BigNumbers OpenSSL::Crypto OpenSSL::SSL ${CMAKE_DL_LIBS} ${CMAKE_THREAD_LIBS_INIT})
target_compile_definitions(ECPoint PRIVATE EXPORT_ECPoint)
set_property(TARGET ECPoint PROPERTY FOLDER "core")

#install(FILES ${ECPoint_HPP_FILES_PUBLIC} DESTINATION "include/ECPoint" COMPONENT core)
#install(TARGETS ECPoint DESTINATION "lib" COMPONENT core)


