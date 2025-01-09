set(ABY3_HOME "/home/jwj/aby3")

include_directories(${ABY3_HOME})
include_directories(${ABY3_HOME}/aby3)
include_directories(${ABY3_HOME}/aby3-DB)
include_directories(${CMAKE_SOURCE_DIR}/examples/)
include_directories(${CMAKE_SOURCE_DIR})
include_directories(/home/jwj/aby3/thirdparty/unix/include)

# add_executable(add_example add_example.cpp)
# add_executable(add_example intersection.cpp)
# add_executable(add_example add_test.cpp)
# add_executable(add_example radix_sort.cpp)
# add_executable(add_example radix_sort_sb.cpp)
# add_executable(add_example radix_sort_si.cpp)
add_executable(add_example radix_sort_si2.cpp)

# add_executable(add_example reshare_test.cpp)

#
# add_executable(add_example test_demo_add_mult.cpp)
# add_executable(add_example read_sbmatrix.cpp)
# add_executable(add_example read_si64matrix.cpp)
target_link_libraries(add_example com-psi)
target_link_libraries(add_example aby3-ML)
target_link_libraries(add_example com-psi_Tests)
target_link_libraries(add_example aby3_Tests)
target_link_libraries(add_example oc::tests_cryptoTools)
