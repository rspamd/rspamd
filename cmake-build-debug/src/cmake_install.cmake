# Install script for directory: /home/fum/CLionProjects/rspamd/src

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Debug")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/rspamd-3.9.0"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/rspamd"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      file(RPATH_CHECK
           FILE "${file}"
           RPATH "/usr/local/lib/rspamd")
    endif()
  endforeach()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE EXECUTABLE FILES
    "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/rspamd-3.9.0"
    "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/rspamd"
    )
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/rspamd-3.9.0"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/rspamd"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      file(RPATH_CHANGE
           FILE "${file}"
           OLD_RPATH "/usr/local/lib:/usr/local/lib/x86_64-linux-gnu:/usr/local/lib64:/home/fum/CLionProjects/rspamd/cmake-build-debug/src:/home/fum/CLionProjects/rspamd/cmake-build-debug/contrib/replxx:/home/fum/CLionProjects/rspamd/cmake-build-debug/contrib/aho-corasick:/home/fum/CLionProjects/rspamd/cmake-build-debug/contrib/libev:/home/fum/CLionProjects/rspamd/cmake-build-debug/contrib/kann:"
           NEW_RPATH "/usr/local/lib/rspamd")
      if(CMAKE_INSTALL_DO_STRIP)
        execute_process(COMMAND "/usr/bin/strip" "${file}")
      endif()
    endif()
  endforeach()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/lib/rspamd/librspamd-server.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/lib/rspamd/librspamd-server.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/lib/rspamd/librspamd-server.so"
         RPATH "/usr/local/lib/rspamd")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/lib/rspamd/librspamd-server.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/lib/rspamd" TYPE SHARED_LIBRARY FILES "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/librspamd-server.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/lib/rspamd/librspamd-server.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/lib/rspamd/librspamd-server.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/lib/rspamd/librspamd-server.so"
         OLD_RPATH "/usr/local/lib:/usr/local/lib/x86_64-linux-gnu:/usr/local/lib64:/home/fum/CLionProjects/rspamd/cmake-build-debug/contrib/replxx:/home/fum/CLionProjects/rspamd/cmake-build-debug/contrib/aho-corasick:/home/fum/CLionProjects/rspamd/cmake-build-debug/contrib/libev:/home/fum/CLionProjects/rspamd/cmake-build-debug/contrib/kann:"
         NEW_RPATH "/usr/local/lib/rspamd")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/lib/rspamd/librspamd-server.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/home/fum/CLionProjects/rspamd/cmake-build-debug/src/lua/cmake_install.cmake")
  include("/home/fum/CLionProjects/rspamd/cmake-build-debug/src/libcryptobox/cmake_install.cmake")
  include("/home/fum/CLionProjects/rspamd/cmake-build-debug/src/libutil/cmake_install.cmake")
  include("/home/fum/CLionProjects/rspamd/cmake-build-debug/src/libserver/cmake_install.cmake")
  include("/home/fum/CLionProjects/rspamd/cmake-build-debug/src/libmime/cmake_install.cmake")
  include("/home/fum/CLionProjects/rspamd/cmake-build-debug/src/libstat/cmake_install.cmake")
  include("/home/fum/CLionProjects/rspamd/cmake-build-debug/src/client/cmake_install.cmake")
  include("/home/fum/CLionProjects/rspamd/cmake-build-debug/src/rspamadm/cmake_install.cmake")

endif()

