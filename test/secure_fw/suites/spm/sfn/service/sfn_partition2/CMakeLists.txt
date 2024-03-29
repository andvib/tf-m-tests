#-------------------------------------------------------------------------------
# Copyright (c) 2021-2022, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0079 NEW)

add_library(tfm_app_rot_partition_sfn2 STATIC)

target_sources(tfm_app_rot_partition_sfn2
    PRIVATE
        sfn_partition2.c
)

target_include_directories(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/generated/secure_fw/test_services/sfn_partition2
)

# The generated sources
target_sources(tfm_app_rot_partition_sfn2
    PRIVATE
        ${CMAKE_BINARY_DIR}/generated/secure_fw/test_services/sfn_partition2/auto_generated/intermedia_sfn_partition2.c
)
target_sources(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/generated/secure_fw/test_services/sfn_partition2/auto_generated/load_info_sfn_partition2.c
)

target_include_directories(tfm_app_rot_partition_sfn2
    PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        ${CMAKE_BINARY_DIR}/generated/secure_fw/test_services/sfn_partition2
        ${CMAKE_CURRENT_SOURCE_DIR}/../
)

target_link_libraries(tfm_app_rot_partition_sfn2
    PRIVATE
        tfm_secure_api
        psa_interface
        platform_s
        tfm_sprt
)

############################ Partition Defs ####################################
target_link_libraries(tfm_partitions
    INTERFACE
        tfm_app_rot_partition_sfn2
)
target_compile_definitions(tfm_partition_defs
    INTERFACE
        TFM_PARTITION_SFN2
)
