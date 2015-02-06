# Check for assembler option specified

function(asm_op output_var op description)
	SET(asm_code "
	${op}
	")
	file(WRITE "${CMAKE_BINARY_DIR}/asm.S" "${asm_code}")
	try_compile(HAVE_OP 
			"${CMAKE_BINARY_DIR}"
            "${CMAKE_BINARY_DIR}/asm.S"
            CMAKE_FLAGS "-DCMAKE_ASM_LINK_EXECUTABLE='echo not linking now...'")
    #file(REMOVE "${CMAKE_BINARY_DIR}/asm.s")
    
	if(HAVE_OP)
		MESSAGE(STATUS "Compilation of ${description} asm set is supported")
	else()
		MESSAGE(STATUS "Compilation of ${description} asm set is -NOT- supported")
    endif()
    
  	set(${output_var} "${HAVE_OP}" PARENT_SCOPE)
endfunction()
