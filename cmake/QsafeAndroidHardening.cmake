# Apply to a source-built Android executable or library.
function(qsafe_harden_android_target target)
    if(NOT ANDROID)
        return()
    endif()
    target_compile_options("${target}" PRIVATE
        "$<$<COMPILE_LANGUAGE:C,CXX>:-fstack-protector-strong>"
        "$<$<COMPILE_LANGUAGE:C,CXX>:SHELL:-include \"${CMAKE_CURRENT_FUNCTION_LIST_DIR}/qsafe_fortify.h\">"
    )
    set_property(TARGET "${target}" PROPERTY POSITION_INDEPENDENT_CODE ON)
    get_target_property(kind "${target}" TYPE)
    if(kind STREQUAL "EXECUTABLE")
        target_link_options("${target}" PRIVATE -pie)
    endif()
    if(kind MATCHES "^(EXECUTABLE|SHARED_LIBRARY|MODULE_LIBRARY)$")
        target_link_options("${target}" PRIVATE "LINKER:-z,relro" "LINKER:-z,now" "LINKER:-z,noexecstack")
    endif()
endfunction()
