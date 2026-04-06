# CCSDS Space Packet Protocol (SPP) Wireshark Dissector

[![Build Status](https://github.com/JahazielLem/wireshark-ccsds/actions/workflows/build.yml/badge.svg)](https://github.com/JahazielLem/wireshark-ccsds/actions)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/License-GPL--3.0--or--later-blue.svg)](https://opensource.org/licenses/GPL-3.0)

## Overview
This repository contains a Wireshark dissector written in C for the CCSDS Space Packet Protocol (SPP). The dissector is designed to parse and visualize the Primary Header of space packets as defined in the CCSDS 133.0-B-2 standard.The plugin provides a detailed breakdown of the 6-byte Primary Header, including packet identification, sequence control, and packet length, while offering user-configurable preferences for handling non-standard implementations.

## User Preferences
The dissector adds a "CCSDS SPP" entry under the Edit > Preferences > Protocols menu:
- **Endianness**: Choose between Big Endian (Standard) and Little Endian for hardware-specific implementations.
- **Secondary Header Lengt**h: Define the length of the secondary header in bytes. This ensures the dissector correctly identifies where the packet payload begins.

## Compile
To compile this plugin first checkout Wireshark source code to your preferred wireshark version. Then, you need to clone this repository onto the epan plugins folder inside wireshark:

```shell
cd plugins/epan/
git clone https://github.com/JahazielLem/wireshark-ccsds grccsds
cd ../../
```

In Wireshark main directory, the project must be configured indicating there is an extra plugin.

```shell
cmake -B build -S . -DCUSTOM_PLUGIN_SRC_DIR=plugins/epan/grccsds
```

You may now build the plugin target alone witout having to compile the full Wireshark source code:

```shell
cmake --build build --target grccsds
```