# CMakeLists.txt
#
# SPDX-FileCopyrightText: © 2025 Kevin Leon
# SPDX-License-Identifier: GPL-3.0-or-later

include(WiresharkPlugin)

# Plugin name and version info (major minor micro extra)
set_module_info(ccsds_spp 0 0 1 0)

set(DISSECTOR_SRC
	ccsds_spp.c
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
)

set_source_files_properties(
	${PLUGIN_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

register_plugin_files(plugin.c
	plugin
	${DISSECTOR_SRC}
)

add_wireshark_plugin_library(ccsds_spp epan)

target_link_libraries(ccsds_spp epan)

install_plugin(ccsds_spp epan)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
CHECKAPI(
	NAME
				ccsds_spp
	SWITCHES
			--group dissectors-prohibited
			--group dissectors-restricted
	SOURCES
			${DISSECTOR_SRC}
			${DISSECTOR_HEADERS}
)

# This is a subtarget of the virtual ccsds target
add_dependencies(grccsds ccsds_spp)