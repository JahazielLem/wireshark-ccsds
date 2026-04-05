# CMakeLists.txt
#
# SPDX-FileCopyrightText: © 2026 Kevin Leon
# SPDX-License-Identifier: GPL-3.0-or-later

cmake_minimum_required(VERSION 3.10)

project(grccsds)

# Create a virtual target that groups all CatSniffer targets
add_custom_target(grccsds ALL)

add_subdirectory(spp)