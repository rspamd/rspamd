# Check for assembler option specified

MACRO(asm_op output_var description)
    IF(NOT ${output_var})
    	file(WRITE "${CMAKE_BINARY_DIR}/asm.S" "${ASM_CODE}")
    	try_compile(HAVE_OP 
    			"${CMAKE_BINARY_DIR}"
                "${CMAKE_BINARY_DIR}/asm.S"
                CMAKE_FLAGS "-DCMAKE_ASM_LINK_EXECUTABLE='echo not linking now...'")
        
    	if(HAVE_OP)
    		MESSAGE(STATUS "Compilation of ${description} asm set is supported")
    	else()
    		MESSAGE(STATUS "Compilation of ${description} asm set is -NOT- supported")
        endif()
        
      	set(${output_var} "${HAVE_OP}" CACHE INTERNAL "${description}")
  	ENDIF()
ENDMACRO()
