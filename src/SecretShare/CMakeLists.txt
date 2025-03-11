
set(SecretShare_HPP_FILES_PUBLIC # Keep alphabet order
  ${CMAKE_CURRENT_SOURCE_DIR}/KeyShare.h
  ${CMAKE_CURRENT_SOURCE_DIR}/SecretSplit.h
)

set(SecretShare_CPP_FILES # Keep alphabet order
  ${CMAKE_CURRENT_SOURCE_DIR}/KeyShare.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/SecretSplit.cc
)

set(SecretShare_SOURCE_FILES ${SecretShare_HPP_FILES} ${SecretShare_CPP_FILES})
add_library(SecretShare ${SecretShare_SOURCE_FILES})

target_link_libraries(SecretShare OpenSSL::Crypto OpenSSL::SSL ${CMAKE_DL_LIBS} ${CMAKE_THREAD_LIBS_INIT})
target_compile_definitions(SecretShare PRIVATE EXPORT_SecretShare)
set_property(TARGET SecretShare PROPERTY FOLDER "core")



#install(FILES ${BigNumbers_HPP_FILES_PUBLIC} DESTINATION "include/BigNumbers" COMPONENT core)
#install(TARGETS BigNumbers DESTINATION "lib" COMPONENT core)

