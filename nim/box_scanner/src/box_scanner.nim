# This is just an example to get you started. A typical hybrid package
# uses this file as the main entry point of the application.

import std/strformat
import box_scanner/file_management
import box_scanner/nmap

when isMainModule:
  echo "-- HTB Box Scanner --"
  echo "Warming up..."
  let host = "topology.htb"
  initializeDataDirs(host)

  echo "Running nmap scan..."
  nmapScan(host)
  let report = parseNmapReport(host)
  if report.hostStatus == Up:
    echo &"Host {host} is up"
    echo "Open ports:"
    for port in report.openPorts:
      echo port
  else:
    echo &"Host {host} is down"
    quit()
