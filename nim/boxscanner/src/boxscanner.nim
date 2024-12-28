import std/[strformat, cmdline, posix, terminal]
import boxscanner/[filemanagement, nmap, requirementscheck, wordlists, fuzzer, fingerprint]

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
    if (options == "--no-cache"):
      styledEcho(fgYellow, "Clearing cache...")
      clearCache(host)

  echo "Setting up cache..."
  initializeDataDirs(host)
  echo "Setting up wordlists..."
  setupWordlists()
  echo "Setting up hostfile..."
  updateHostsFile(host, ip)

  echo ""
  echo &"Scanning for open ports on {host} with nmap..."
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

  echo ""
  echo "Basic fingerprinting of ports..."
  let fingerprintedPorts = fingerprintPorts(host, nmapReport.openPorts)

  echo ""
  echo &"Determining optimal fuzzing parameters for {host}..."
  let favorableConfigurations = determineFuzzParameters(host, fingerprintedPorts)
  echo ""
  let fuzzResults = fuzzVhostsByConfigurationFavorability(favorableConfigurations)

  echo ""
  if fuzzResults.len > 0:
    styledEcho(fgGreen, "Successfully Identified the following vhosts:")
    for r in fuzzResults:
      echo &"- {r}"

    echo "\nUpdating hostsfile with the newly found hosts..."
    for r in fuzzResults:
      updateHostsFile(r, ip)
  else:
    styledEcho(fgYellow, "Did not identify any vhosts.")

  # Todo, crawl webpages to try to find further vhosts in the source frontend code
  # ie, napper.htb


when isMainModule:
  mainScan()
