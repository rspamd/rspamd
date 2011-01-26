# PkgCreate creates FreeBSD package for cmake
# USAGE : ADD_FREEBSD_PACKAGE ( PKG_TARGET_NAME [DESCRIPTION] )

FIND_PROGRAM(PKGCREATE
    NAMES pkg_create
    PATHS "/usr/sbin")

IF ( PKGCREATE )
    GET_FILENAME_COMPONENT(PKGCREATE_PATH ${PKGCREATE} ABSOLUTE)
    MESSAGE(STATUS "Found pkg_create : ${PKGCREATE_PATH}")
    SET(PKGCREATE_FOUND "YES")
ELSE ( PKGCREATE ) 
    MESSAGE(STATUS "pkg_create NOT found. package generation will not be available")
    SET(PKGCREATE_FOUND "NO")
ENDIF ( PKGCREATE )

MACRO(ADD_FREEBSD_PACKAGE PKGNAME PLIST_FILE)
  # let's create a directory to call 'make install DESTDIR=...' into:
  SET ( FREEBSD_DIR  ${CMAKE_BINARY_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}-${PACKAGE_RELEASE} )
  FILE ( REMOVE ${FREEBSD_DIR} )
  FILE ( MAKE_DIRECTORY ${FREEBSD_DIR} )
  FILE ( MAKE_DIRECTORY ${FREEBSD_DIR}/pkg )
  # Calling "make install DESTDIR=${FREEBSD_DIR}"
  ADD_CUSTOM_TARGET(pkg_destdir_install
    COMMAND ${CMAKE_MAKE_PROGRAM} install CMAKE_INSTALL_PREFIX=/ DESTDIR=${FREEBSD_DIR}
    DEPENDS ${CMAKE_BINARY_DIR}/cmake_install.cmake	  
    COMMENT "Installing with DESTDIR = ${FREEBSD_DIR}"
  )
  ADD_DEPENDENCIES(pkg_destdir_install pkg_destdir_preinstall)
  ADD_CUSTOM_TARGET(pkg_destdir_preinstall
    COMMAND ${CMAKE_COMMAND} -DCMAKE_INSTALL_PREFIX=/ -DDESTDIR=${FREEBSD_DIR} .
    DEPENDS ${CMAKE_BINARY_DIR}/cmake_install.cmake	  
    COMMENT "Configuring with DESTDIR = ${FREEBSD_DIR}"
  )
  ADD_DEPENDENCIES(pkg_destdir_preinstall all preinstall)
 
 
  ADD_CUSTOM_COMMAND(
    OUTPUT  ${CMAKE_BINARY_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}-${PACKAGE_RELEASE}.tbz
    COMMAND ${PKGCREATE_PATH} -c -"${PACKAGE_DESCRIPTION_SUMMARY}" 
        -d -"${PACKAGE_DESCRIPTION}"
        -f ${PLIST_FILE}
        -p ${FREEBSD_DIR}
        ${CMAKE_BINARY_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}-${PACKAGE_RELEASE}.tbz
    # removing control, so its (re)generated each time we need to build the package
    DEPENDS ${PLIST_FILE}
    COMMENT   "Generating freebsd package"
  )
  
    # the final target:
  ADD_CUSTOM_TARGET(${PKGNAME}_pkg
    DEPENDS ${CMAKE_BINARY_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}-${PACKAGE_RELEASE}.tbz
  )
  
  ADD_DEPENDENCIES(${PKGNAME}_pkg pkg_destdir_install)
ENDMACRO(ADD_FREEBSD_PACKAGE PKGNAME)