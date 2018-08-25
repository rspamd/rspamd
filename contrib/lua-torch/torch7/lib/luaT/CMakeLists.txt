# avoid some cmake warnings

INCLUDE_DIRECTORIES(${LUA_INCDIR})
IF(LUALIB)
  LINK_DIRECTORIES(${LUA_LIBDIR}) # note: must be done before defining target
ENDIF()

ADD_LIBRARY(luaT STATIC luaT.h luaT.c)

IF(LUALIB)
  TARGET_LINK_LIBRARIES(luaT ${LUALIB}) # must be done after ;)
ENDIF()
