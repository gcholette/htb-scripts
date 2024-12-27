#!/bin/bash

nimble build -d:ssl -d:ThreadPoolSize=8 -d:FixedChanSize=16
sudo ./boxscanner $@
