# wireshark-ccsds
Wireshark dissectors for CCSDS protocols.

# Compile
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