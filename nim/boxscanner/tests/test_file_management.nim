import unittest

from std/envvars import getEnv
import box_scanner/file_management

test "getDataDir returns the correct path on linux":
  check getDataDir().string == getEnv("HOME") & "/.local/share/box_scanner/"
