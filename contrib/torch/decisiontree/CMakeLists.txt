SET(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR})

CMAKE_MINIMUM_REQUIRED(VERSION 2.6 FATAL_ERROR)
CMAKE_POLICY(VERSION 2.6)

SET(src
   init.c
   hash_map.c
)
SET(luasrc
   _env.lua
   benchmark.lua
   CartNode.lua
   CartTrainer.lua
   CartTree.lua
   DataSet.lua
   DecisionForest.lua
   DecisionForestTrainer.lua
   DecisionTree.lua
   DFD.lua
   GiniState.lua
   GradientBoostState.lua
   GradientBoostTrainer.lua
   init.lua
   LogitBoostCriterion.lua
   math.lua
   MSECriterion.lua
   RandomForestTrainer.lua
   Sparse2Dense.lua
   SparseTensor.lua
   test.lua
   TreeState.lua
   utils.lua
   WorkPool.lua
)

IF (WITH_OPENMP)
   FIND_PACKAGE(OpenMP)
   IF(OPENMP_FOUND)
      MESSAGE(STATUS "Compiling with OpenMP support")
      SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
      SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
      SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
   ENDIF(OPENMP_FOUND)
ENDIF (WITH_OPENMP)

ADD_TORCH_PACKAGE(decisiontree "${src}" "${luasrc}" "A decision tree library, for Torch")
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})
### Torch packages supposes libraries prefix is "lib"
SET_TARGET_PROPERTIES(decisiontree PROPERTIES
        PREFIX "lib"
        IMPORT_PREFIX "lib")
TARGET_LINK_LIBRARIES(decisiontree ${TH_LIBRARIES})
INSTALL(TARGETS decisiontree DESTINATION ${RSPAMD_LIBDIR})
