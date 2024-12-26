import unittest

import box_scanner/nmap

test "parseNmapReport works":
  # todo Add mocks
  check parseNmapReport("topology.htb") == NmapReport(
    hostStatus: Up, 
    openPorts: @[22, 80], 
    scanStatus: "success", 
    osInfo: HostOSInfo(accuracy: 0.0, name: "")
  )
