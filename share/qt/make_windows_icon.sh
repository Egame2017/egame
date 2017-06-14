#!/bin/bash
# create multiresolution windows icon
ICON_DST=../../src/qt/res/icons/way.ico

convert ../../src/qt/res/icons/way-16.png ../../src/qt/res/icons/way-32.png ../../src/qt/res/icons/way-48.png ../../src/qt/res/icons/way-64.png ../../src/qt/res/icons/way-128.png ../../src/qt/res/icons/way-256.png ${ICON_DST}
