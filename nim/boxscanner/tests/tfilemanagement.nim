import unittest
import boxscanner/filemanagement

test "getDataDir returns the correct path on linux":
  check getDataDir().string == "/var/cache/boxscanner/"
