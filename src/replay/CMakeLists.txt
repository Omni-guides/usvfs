cmake_minimum_required(VERSION 3.16)

# fork: file-API trace replayer (see HANDOFF.md)
add_executable(replay main.cpp ${PROJECT_SOURCE_DIR}/src/shared/ntdll_declarations.cpp)
target_link_libraries(replay PRIVATE shared Psapi)
set_target_properties(replay
    PROPERTIES
    RUNTIME_OUTPUT_NAME replay${ARCH_POSTFIX}
    RUNTIME_OUTPUT_DIRECTORY_DEBUG ${USVFS_BINDIR}
    RUNTIME_OUTPUT_DIRECTORY_RELEASE ${USVFS_BINDIR}
)
