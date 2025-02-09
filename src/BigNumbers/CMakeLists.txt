#################################################################
#  Date                                                         #
#  Author           nChain's employees                          #
#                                                               #
#  
#################################################################

set(BigNumbers_HPP_FILES_PUBLIC # Keep alphabet order
  ${CMAKE_CURRENT_SOURCE_DIR}/BigNumbers.h
)

set(BigNumbers_HPP_FILES ${BigNumbers_HPP_FILES_PUBLIC})

set(BigNumbers_CPP_FILES # Keep alphabet order
  ${CMAKE_CURRENT_SOURCE_DIR}/BigNumbers.cpp
)

set(BigNumbers_SOURCE_FILES ${BigNumbers_HPP_FILES} ${BigNumbers_CPP_FILES})
add_library(BigNumbers ${BigNumbers_SOURCE_FILES})

#pybind11::module
target_link_libraries(BigNumbers OpenSSL::Crypto OpenSSL::SSL ${CMAKE_DL_LIBS} ${CMAKE_THREAD_LIBS_INIT})
target_compile_definitions(BigNumbers PRIVATE EXPORT_BigNumbers)
set_property(TARGET BigNumbers PROPERTY FOLDER "core")



#install(FILES ${BigNumbers_HPP_FILES_PUBLIC} DESTINATION "include/BigNumbers" COMPONENT core)
#install(TARGETS BigNumbers DESTINATION "lib" COMPONENT core)

