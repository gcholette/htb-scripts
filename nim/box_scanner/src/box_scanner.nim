import std/[strformat, cmdline]
import box_scanner/[file_management, nmap, requirements_check]

when isMainModule:
  echo "-- HTB Box Scanner --"

  if paramCount() < 2:
    echo "Usage: <target-host> <target-ip>"
    echo "Example: ./box_scanner topology.htb 10.10.10.10"
    quit(1)


  let host = paramStr(1)
  let ip = paramStr(2)
  echo "Warming up..."
  checkRequirements()
  initializeDataDirs(host)
  updateHostsFile(host, ip)

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
