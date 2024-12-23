# This is just an example to get you started. You may wish to put all of your
# tests into a single file, or separate them into multiple `test1`, `test2`
# etc. files (better names are recommended, just make sure the name starts with
# the letter 't').
#
# To run these tests, simply execute `nimble test`.

import unittest

from std/envvars import getEnv
import box_scanner/file_management

test "getDataDir returns the correct path on linux":
  check getDataDir().string == getEnv("HOME") & "/.local/share/box_scanner/"
