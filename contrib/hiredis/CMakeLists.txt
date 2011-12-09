# Hiredis compilation target

SET(LIBHIREDISSRC async.c
                  dict.c
                  hiredis.c
                  net.c
                  sds.c)

ADD_LIBRARY(hiredis STATIC ${LIBHIREDISSRC})
IF(CMAKE_COMPILER_IS_GNUCC)
SET_TARGET_PROPERTIES(hiredis PROPERTIES COMPILE_FLAGS "-fno-strict-aliasing")
ENDIF(CMAKE_COMPILER_IS_GNUCC)

TARGET_LINK_LIBRARIES(hiredis ${CMAKE_REQUIRED_LIBRARIES}) 