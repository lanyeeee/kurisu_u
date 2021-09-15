aux_source_directory(. SRCKURISU)
aux_source_directory(./fmt SRCFMT)

add_library(kurisu STATIC ${SRCKURISU} ${SRCFMT})

include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_SOURCE_DIR}/include/kurisu)
