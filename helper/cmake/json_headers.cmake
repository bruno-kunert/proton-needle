# An explicit override is authoritative: never silently substitute another copy.
if(NOT NLOHMANN_INCLUDE_DIR)
    unset(NLOHMANN_INCLUDE_DIR CACHE)
    find_path(NLOHMANN_INCLUDE_DIR NAMES nlohmann/json.hpp
        PATHS /usr/include NO_CMAKE_FIND_ROOT_PATH)
endif()
if(NOT NLOHMANN_INCLUDE_DIR OR
   NOT EXISTS "${NLOHMANN_INCLUDE_DIR}/nlohmann/json.hpp" OR
   IS_DIRECTORY "${NLOHMANN_INCLUDE_DIR}/nlohmann/json.hpp")
    message(FATAL_ERROR
        "nlohmann JSON headers not found. Install nlohmann-json3-dev or set "
        "NLOHMANN_INCLUDE_DIR to an existing include root containing nlohmann/json.hpp.")
endif()
get_filename_component(NLOHMANN_INCLUDE_DIR "${NLOHMANN_INCLUDE_DIR}" REALPATH)
set(NLOHMANN_INCLUDE_DIR "${NLOHMANN_INCLUDE_DIR}" CACHE PATH
    "nlohmann JSON include root for the Windows helper" FORCE)
