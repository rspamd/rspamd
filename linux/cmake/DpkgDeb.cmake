# DpkgDeb : Create debian packages for your projects and sub projects. Written by Mehdi Rabah
# Was heavily inspired by UseDebian (Mathieu Malaterre) and UseRPMTools (TSP Team) modules

# need /usr/bin/dpkg

# USAGE : ADD_DEBIAN_PACKAGE ( DEB_TARGET_NAME [CONTROL_FILE] )  
# You need to set the control file either by setting these variables
# or by giving as second parameter the path to the control file you want to use
# If you choose to set the variables, you must set the mandatory variables:
# (see man 5 deb-control for more details)
#
# -- MANDATORY Variables
# Package: ${PACKAGE_NAME}. Must be a lowercase string
# Version: ${PACKAGE_VERSION}. Like 1.1.0
# Release: ${PACKAGE_RELEASE}. A number beetween 0 and 9
# Maintainer: ${PACKAGE_MAINTAINER_NAME} and ${PACKAGE_MAINTAINER_EMAIL}. 
# Description summary: ${PACKAGE_DESCRIPTION_SUMMARY}. Project summary
# Description : ${PACKAGE_DESCRIPTION}. Warning : for now, use of special characters (>, (, ', ... ) is not allowed
#
# -- OPTIONAL Variables 
# Architecture: ${DEBIAN_ARCHITECTURE}, by default i386 for intel on debian like
# Depends: ${PACKAGE_DEPENDS}
# Section: ${PACKAGE_SECTION}
# Priority: ${PACKAGE_PRIORITY}
# Essential: ${PACKAGE_ESSENTIAL}
# Source: ${PACKAGE_SOURCE}
# Pre-Depends: ${PACKAGE_PREDEPENDS}
# Recommends: ${PACKAGE_RECOMMENDS}
# Suggests: ${PACKAGE_SUGGESTS}
# Breaks: ${PACKAGE_BREAKS}
# Conflicts: ${PACKAGE_CONFLICTS}
# Replaces: ${PACKAGE_REPLACES}
# Provides: ${PACKAGE_PROVIDES}

# TODO: Make clean does not clean the DEBIAN_DIR folder
# TODO: use objdump -p to automatically generate depedencies (cf dh_makeshlibs)

FIND_PROGRAM(DPKG
    NAMES dpkg-deb
    PATHS "/usr/bin")

IF ( DPKG )
    GET_FILENAME_COMPONENT(DPKG_PATH ${DPKG} ABSOLUTE)
    MESSAGE(STATUS "Found dpkg-deb : ${DPKG_PATH}")
    SET(DPKG_FOUND "YES")
ELSE ( DPKG ) 
    MESSAGE(STATUS "dpkg-deb NOT found. deb generation will not be available")
    SET(DPKG_FOUND "NO")
ENDIF ( DPKG )

# Main and only command of this module. For more details, visit this webpage
# http://tldp.org/HOWTO/Debian-Binary-Package-Building-HOWTO/
MACRO(ADD_DEBIAN_PACKAGE DEBNAME)

  SET ( CONTROL_FILE ${PROJECT_BINARY_DIR}/control_${PROJECT_NAME} )
  
  # First choice for control file : user defined variables 
  IF ("${ARGV1}" STREQUAL "")

      # Check if the mandatory variables are here
      IF(NOT PACKAGE_NAME OR NOT PACKAGE_VERSION OR NOT DEFINED PACKAGE_RELEASE OR
         NOT PACKAGE_MAINTAINER_NAME OR NOT PACKAGE_MAINTAINER_EMAIL OR 
         NOT PACKAGE_DESCRIPTION_SUMMARY OR NOT PACKAGE_DESCRIPTION )
         message ( FATAL_ERROR "ADD_DEBIAN_PACKAGE command was not correctly configured for ${PROJECT_NAME}. See the documentation for more details" )
      ENDIF(NOT PACKAGE_NAME OR NOT PACKAGE_VERSION OR NOT DEFINED PACKAGE_RELEASE OR
         NOT PACKAGE_MAINTAINER_NAME OR NOT PACKAGE_MAINTAINER_EMAIL OR 
         NOT PACKAGE_DESCRIPTION_SUMMARY OR NOT PACKAGE_DESCRIPTION )

      IF(NOT DEBIAN_ARCHITECTURE)
	  	EXECUTE_PROCESS(COMMAND "/usr/bin/dpkg" "--print-architecture" OUTPUT_VARIABLE DEBIAN_ARCHITECTURE OUTPUT_STRIP_TRAILING_WHITESPACE)
      ENDIF(NOT DEBIAN_ARCHITECTURE)

      # Writing the control file
      # see man 5 deb-control for more details
      ADD_CUSTOM_COMMAND(
        OUTPUT ${CONTROL_FILE}
        COMMAND   ${CMAKE_COMMAND} -E echo 
         "Package: ${PACKAGE_NAME}" > ${CONTROL_FILE}
         
        COMMAND   ${CMAKE_COMMAND} -E echo
         "Version: ${PACKAGE_VERSION}" >> ${CONTROL_FILE}
        
        COMMAND   ${CMAKE_COMMAND} -E echo
         "Maintainer: ${PACKAGE_MAINTAINER_NAME}"
         \"<"${PACKAGE_MAINTAINER_EMAIL}\">" >> ${CONTROL_FILE}

        COMMAND   ${CMAKE_COMMAND}
        ARGS      -E echo "Architecture: ${DEBIAN_ARCHITECTURE}" >> ${CONTROL_FILE}
      )   

      IF ( DEFINED PACKAGE_DEPENDS )
        ADD_CUSTOM_COMMAND( OUTPUT ${CONTROL_FILE}
          COMMAND   ${CMAKE_COMMAND} -E echo
           "Depends: ${PACKAGE_DEPENDS}" >> ${CONTROL_FILE}
          APPEND )   
      ENDIF ( DEFINED PACKAGE_DEPENDS )

      IF ( DEFINED PACKAGE_SECTION )
        ADD_CUSTOM_COMMAND( OUTPUT ${CONTROL_FILE}
          COMMAND   ${CMAKE_COMMAND} -E echo
           "Section: ${PACKAGE_SECTION}" >> ${CONTROL_FILE}
          APPEND )   
      ENDIF ( DEFINED PACKAGE_SECTION)
      IF ( DEFINED PACKAGE_HOMEPAGE )
        ADD_CUSTOM_COMMAND( OUTPUT ${CONTROL_FILE}
          COMMAND   ${CMAKE_COMMAND} -E echo
           "Homepage: ${PACKAGE_HOMEPAGE}" >> ${CONTROL_FILE}
          APPEND )   
      ENDIF ( DEFINED PACKAGE_HOMEPAGE)
      
      IF ( DEFINED PACKAGE_PRIORITY )
        ADD_CUSTOM_COMMAND( OUTPUT ${CONTROL_FILE}
          COMMAND   ${CMAKE_COMMAND} -E echo
           "Priority: ${PACKAGE_PRIORITY}" >> ${CONTROL_FILE}
          APPEND)   
      ENDIF ( DEFINED PACKAGE_PRIORITY)

      IF ( DEFINED PACKAGE_ESSENTIAL )
        ADD_CUSTOM_COMMAND( OUTPUT ${CONTROL_FILE}
          COMMAND   ${CMAKE_COMMAND} -E echo
           "Essential: ${PACKAGE_ESSENTIAL}" >> ${CONTROL_FILE}
          APPEND)   
      ENDIF ( DEFINED PACKAGE_ESSENTIAL)

      IF ( DEFINED PACKAGE_SOURCE )
        ADD_CUSTOM_COMMAND( OUTPUT ${CONTROL_FILE}
          COMMAND   ${CMAKE_COMMAND} -E echo
           "Source: ${PACKAGE_SOURCE}" >> ${CONTROL_FILE}
          APPEND)   
      ENDIF ( DEFINED PACKAGE_SOURCE)

      IF ( DEFINED PACKAGE_PREDEPENDS )
        ADD_CUSTOM_COMMAND( OUTPUT ${CONTROL_FILE}
          COMMAND   ${CMAKE_COMMAND} -E echo
           "Pre-Depends: ${PACKAGE_PREDEPENDS}" >> ${CONTROL_FILE}
          APPEND)   
      ENDIF ( DEFINED PACKAGE_PREDEPENDS )

      IF ( DEFINED PACKAGE_RECOMMENDS )
        ADD_CUSTOM_COMMAND( OUTPUT ${CONTROL_FILE}
          COMMAND   ${CMAKE_COMMAND} -E echo
           "Recommends: ${PACKAGE_RECOMMENDS}" >> ${CONTROL_FILE}
          APPEND)   
      ENDIF ( DEFINED PACKAGE_RECOMMENDS)

      IF ( DEFINED PACKAGE_SUGGESTS )
        ADD_CUSTOM_COMMAND( OUTPUT ${CONTROL_FILE}
          COMMAND   ${CMAKE_COMMAND} -E echo
           "Suggests: ${PACKAGE_SUGGESTS}" >> ${CONTROL_FILE}
          APPEND)   
      ENDIF ( DEFINED PACKAGE_SUGGESTS )

      IF ( DEFINED PACKAGE_BREAKS )
        ADD_CUSTOM_COMMAND( OUTPUT ${CONTROL_FILE}
          COMMAND   ${CMAKE_COMMAND} -E echo
           "Breaks: ${PACKAGE_BREAKS}" >> ${CONTROL_FILE}
          APPEND)   
      ENDIF ( DEFINED PACKAGE_BREAKS )

      IF ( DEFINED PACKAGE_CONFLICTS )
        ADD_CUSTOM_COMMAND( OUTPUT ${CONTROL_FILE}
          COMMAND   ${CMAKE_COMMAND} -E echo
           "Conflicts: ${PACKAGE_CONFLICTS}" >> ${CONTROL_FILE}
          APPEND)   
      ENDIF ( DEFINED PACKAGE_CONFLICTS )

      IF ( DEFINED PACKAGE_REPLACES )
        ADD_CUSTOM_COMMAND( OUTPUT ${CONTROL_FILE}
          COMMAND   ${CMAKE_COMMAND} -E echo
           "Replaces: ${PACKAGE_REPLACES}" >> ${CONTROL_FILE}
          APPEND)   
      ENDIF ( DEFINED PACKAGE_REPLACES )

      IF ( DEFINED PACKAGE_PROVIDES )
        ADD_CUSTOM_COMMAND( OUTPUT ${CONTROL_FILE}
          COMMAND   ${CMAKE_COMMAND} -E echo
           "Provides: ${PACKAGE_PROVIDES}" >> ${CONTROL_FILE}
          APPEND)   
      ENDIF ( DEFINED PACKAGE_PROVIDES )
      
      ADD_CUSTOM_COMMAND( OUTPUT ${CONTROL_FILE}
        COMMAND   ${CMAKE_COMMAND} -E echo
         "Description: ${PACKAGE_DESCRIPTION_SUMMARY}" >> ${CONTROL_FILE}
        COMMAND   ${CMAKE_COMMAND} -E echo
         " ." >> ${CONTROL_FILE}
        COMMAND   ${CMAKE_COMMAND} -E echo
         " ${PACKAGE_DESCRIPTION}" >> ${CONTROL_FILE}
        COMMAND   ${CMAKE_COMMAND} -E echo
         " ." >> ${CONTROL_FILE}
        COMMAND   ${CMAKE_COMMAND} -E echo
         "" >> ${CONTROL_FILE}
        COMMENT   "Generating control file"
        APPEND
      )
  ELSE ("${ARGV1}" STREQUAL "")
     ADD_CUSTOM_COMMAND(
        OUTPUT    ${CONTROL_FILE}
        COMMAND   ${CMAKE_COMMAND} -E copy "${ARGV1}" ${CONTROL_FILE}
        COMMENT "Copying user specified control file : ${ARGV1}"
      )
  ENDIF("${ARGV1}" STREQUAL "")
  
  # let's create a directory to call 'make install DESTDIR=...' into:
  SET ( DEBIAN_DIR  ${CMAKE_BINARY_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}-${PACKAGE_RELEASE}_${DEBIAN_ARCHITECTURE} )
  FILE ( REMOVE ${DEBIAN_DIR} )
  FILE ( MAKE_DIRECTORY ${DEBIAN_DIR} )
  FILE ( MAKE_DIRECTORY ${DEBIAN_DIR}/DEBIAN )

  # Calling "make install DESTDIR=${DEBIAN_DIR}"
  ADD_CUSTOM_TARGET(deb_destdir_install
    COMMAND ${CMAKE_MAKE_PROGRAM} install CMAKE_INSTALL_PREFIX=/usr DESTDIR=${DEBIAN_DIR}
    DEPENDS ${CMAKE_BINARY_DIR}/cmake_install.cmake	  
    COMMENT "Installing with DESTDIR = ${DEBIAN_DIR}"
  )
  ADD_DEPENDENCIES(deb_destdir_install deb_destdir_preinstall)
  ADD_CUSTOM_TARGET(deb_destdir_preinstall
    COMMAND ${CMAKE_COMMAND} -DCMAKE_INSTALL_PREFIX=/usr -DDESTDIR=${DEBIAN_DIR} .
    DEPENDS ${CMAKE_BINARY_DIR}/cmake_install.cmake	  
    COMMENT "Configuring with DESTDIR = ${DEBIAN_DIR}"
  )
  ADD_DEPENDENCIES(deb_destdir_preinstall all preinstall)
  
  # Calling dpkg --build 
  ADD_CUSTOM_COMMAND(
    OUTPUT  ${CMAKE_BINARY_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}-${PACKAGE_RELEASE}_${DEBIAN_ARCHITECTURE}.deb
    COMMAND ${CMAKE_COMMAND} -E copy ${CONTROL_FILE} ${DEBIAN_DIR}/DEBIAN/control
    COMMAND ${DPKG_PATH} --build ${DEBIAN_DIR}
    # removing control, so its (re)generated each time we need to build the package
    COMMAND ${CMAKE_COMMAND} -E remove ${CONTROL_FILE}
    DEPENDS ${CONTROL_FILE}
    COMMENT   "Generating deb package"
  )

  # the final target:
  ADD_CUSTOM_TARGET(${DEBNAME}_deb
    DEPENDS ${CMAKE_BINARY_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}-${PACKAGE_RELEASE}_${DEBIAN_ARCHITECTURE}.deb
  )
  
  ADD_DEPENDENCIES(${DEBNAME}_deb deb_destdir_install)

ENDMACRO(ADD_DEBIAN_PACKAGE DEBNAME)
