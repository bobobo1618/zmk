# Copyright (c) 2020 The ZMK Contributors
# SPDX-License-Identifier: MIT

zephyr_include_directories(.)

zephyr_library()

zephyr_library_sources(ma730.c)
zephyr_library_sources_ifdef(CONFIG_MA730_TRIGGER ma730_trigger.c)
