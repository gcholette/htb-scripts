import std/[strformat, cmdline, posix, terminal]
import boxscanner/[filemanagement, nmap, requirementscheck, wordlists]

proc mainScan*() =
  echo ""
  styledEcho(fgCyan,"-- HTB Box Scanner --")

  if not (getuid() == 0):
    styledEcho(fgRed, "boxscanner must be run as root")
    quit(1)

  if paramCount() < 2:
    echo "Usage: <target-host> <target-ip> [...options]"
    echo "Example: ./box_scanner topology.htb 10.10.10.10 --clear-cache"
    quit(1)

  let host = paramStr(1)
  let ip = paramStr(2)
  echo "Warming up..."
  echo "Checking system requirements..."
  checkRequirements()

  if (paramCount() > 2):
    let options = paramStr(3)
    if (options == "--clear-cache"):
      styledEcho(fgYellow, "Clearing cache...")
      clearCache(host)

  echo "Setting up cache..."
  initializeDataDirs(host)
  echo "Setting up wordlists..."
  setupWordlists()
  echo "Setting up hostfile..."
  updateHostsFile(host, ip)

  echo ""
  echo "Running nmap scan..."
  nmapScan(host)
  let nmapReport = parseNmapReport(host)
  if nmapReport.hostStatus == Up:
    styledEcho(fgGreen, &"Host {host} ({ip}) is up")
    if nmapReport.openPorts.len > 0:
      echo "Open ports:"
      for port in nmapReport.openPorts:
        echo &"- {port}"
    else:
      styledEcho(fgYellow, "The scan could not identify any open ports")
  else:
    styledEcho(fgRed, &"Host {host} is down")
    quit()

when isMainModule:
  mainScan()