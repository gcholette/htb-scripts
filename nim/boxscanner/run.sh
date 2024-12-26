#!/bin/bash

nimble build -d:ssl
sudo ./boxscanner $@
