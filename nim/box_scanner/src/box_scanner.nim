# This is just an example to get you started. A typical hybrid package
# uses this file as the main entry point of the application.

import box_scanner/file_management
import box_scanner/nmap


when isMainModule:
  let host = "topology.htb"
  initializeDataDirs(host)
  nmapScan(host)
