# SetupPVSStudio.cmake
# Configures PVS-Studio static code analysis if available

function(SetupPVSStudio)
    # Try to find PVS-Studio analyzer
    find_program(_PVS_STUDIO "pvs-studio-analyzer")

    if (_PVS_STUDIO)
        message(STATUS "Found PVS-Studio analyzer: ${_PVS_STUDIO}")

        # Include the PVS-Studio module
        include(PVS-Studio)

        # Get a list of source directories to analyze
        set(_ANALYZE_TARGETS
                ${PROJECT_NAME}      # Main project
                rspamd-server        # Server component
                rspamadm             # Admin utility
                rspamc              # Client utility
        )

        # Setup analysis target
        pvs_studio_add_target(
                TARGET ${PROJECT_NAME}.analyze         # Target name for running analysis
                ANALYZE ${_ANALYZE_TARGETS}            # What to analyze
                OUTPUT FORMAT errorfile                # Output format
                LOG target_${PROJECT_NAME}.err         # Log file path
                ARGS
                # Additional pvs-studio-analyzer arguments
                --exclude-path "${CMAKE_SOURCE_DIR}/contrib"  # Exclude third-party code
        )

        # Add a help message for the target
        add_custom_command(
                TARGET ${PROJECT_NAME}.analyze
                POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E echo "PVS-Studio analysis complete. Results in target_${PROJECT_NAME}.err"
        )

        # Create a report target that converts the error file to a more readable format
        add_custom_target(${PROJECT_NAME}.analyze-report
                COMMAND ${CMAKE_COMMAND} -E echo "Generating HTML report from PVS-Studio results..."
                COMMAND plog-converter -a GA:1,2,3 -t fullhtml -o pvs-report target_${PROJECT_NAME}.err
                COMMAND ${CMAKE_COMMAND} -E echo "Report generated in pvs-report/ directory"
                DEPENDS ${PROJECT_NAME}.analyze
                COMMENT "Converting PVS-Studio output to HTML report"
                VERBATIM
        )

        message(STATUS "PVS-Studio targets added:")
        message(STATUS "  - ${PROJECT_NAME}.analyze: Run the analysis")
        message(STATUS "  - ${PROJECT_NAME}.analyze-report: Generate HTML report from analysis results")
    else ()
        message(STATUS "PVS-Studio analyzer not found. Static analysis disabled.")
    endif ()
endfunction()
