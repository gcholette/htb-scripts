import std/[strformat, cmdline, posix, terminal, tables]
import boxscanner/[filemanagement, nmap, requirementscheck, wordlists, fuzzer, fingerprint, fnutils]

proc mainScan*() =
  echo ""
  styledEcho(fgCyan,"-- HTB Box Scanner 1.0.0 --")

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
  if fingerprintedPorts.len > 0:
    styledEcho(fgGreen, "Fingerprinted the following:")
    for k, v in fingerprintedPorts:
      echo &"- {k}: {v.service}"

  echo ""
  echo &"Determining optimal fuzzing parameters for {host}..."
  let favorableConfigurations = determineFuzzParameters(host, fingerprintedPorts)
  echo ""
  let fuzzResults = fuzzVhostsByConfigurationFavorability(favorableConfigurations)

  if fuzzResults.len > 0:
    styledEcho(fgGreen, "Successfully Identified the following vhosts:")
    for r in fuzzResults:
      echo &"- {r}"

    echo "\nUpdating hostsfile with the newly found hosts..."
    for r in fuzzResults:
      updateHostsFile(r, ip)
  else:
    styledEcho(fgYellow, "Did not identify any vhosts.")

  echo ""
  styledEcho(fgCyan, "-- Summary --")
  stdout.styledWrite(fgCyan, "Host: ")
  echo &"{host} {ip}"
  styledEcho(fgCyan, "Open ports:")
  if fingerprintedPorts.len > 0:
    for k, v in fingerprintedPorts:
      echo &"- {k}: {v.service}"
  else:
    styledEcho(fgYellow, "Did not identify any open ports.")
  
  styledEcho(fgCyan, "Vhosts:")
  if fuzzResults.len > 0:
    for r in fuzzResults:
      echo &"- {r}"

  else:
    styledEcho(fgYellow, "Did not identify any vhosts.")


  # Todo, crawl webpages to try to find further vhosts in the source frontend code
  # ie, napper.htb


when isMainModule:
  mainScan()
