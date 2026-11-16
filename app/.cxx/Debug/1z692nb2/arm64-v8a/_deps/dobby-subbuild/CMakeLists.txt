# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.22.1-g37088a8)

# We name the project and the target for the ExternalProject_Add() call
# to something that will highlight to the user what we are working on if
# something goes wrong and an error message is produced.

project(dobby-populate NONE)



include(ExternalProject)
ExternalProject_Add(dobby-populate
                     "UPDATE_DISCONNECTED" "False" "URL" "https://github.com/jmpews/Dobby/archive/5dfc8546954ce3b3198132ab13fddb89ee92cdd7.zip"
                    SOURCE_DIR          "/home/hatch/workspace/hozin-pvz-injector/app/.cxx/Debug/1z692nb2/arm64-v8a/_deps/dobby-src"
                    BINARY_DIR          "/home/hatch/workspace/hozin-pvz-injector/app/.cxx/Debug/1z692nb2/arm64-v8a/_deps/dobby-build"
                    CONFIGURE_COMMAND   ""
                    BUILD_COMMAND       ""
                    INSTALL_COMMAND     ""
                    TEST_COMMAND        ""
                    USES_TERMINAL_DOWNLOAD  YES
                    USES_TERMINAL_UPDATE    YES
)


