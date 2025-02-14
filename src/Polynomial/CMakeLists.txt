set(Polynomial_HPP_FILES_PUBLIC # Keep alphabet order
  ${CMAKE_CURRENT_SOURCE_DIR}/LGInterpolator.h
  ${CMAKE_CURRENT_SOURCE_DIR}/Polynomial.h
)
set(Polynomial_HPP_FILES ${Polynomial_HPP_FILES_PUBLIC})

set(Polynomial_CPP_FILES # Keep alphabet order
  ${CMAKE_CURRENT_SOURCE_DIR}/LGInterpolator.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/Polynomial.cpp
)

set(Polynomial_SOURCE_FILES ${Polynomial_HPP_FILES} ${Polynomial_CPP_FILES})
add_library(Polynomial ${LIBS_BUILD_TYPE} ${Polynomial_SOURCE_FILES})

target_link_libraries(Polynomial BigNumbers ECPoint)
set_property(TARGET Polynomial PROPERTY FOLDER "core")


#install(FILES ${Polynomial_HPP_FILES_PUBLIC} DESTINATION "include/Polynomial" COMPONENT core)
#install(TARGETS Polynomial DESTINATION "lib" COMPONENT core)

