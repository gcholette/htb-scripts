import std/[dirs, paths, strutils, sequtils, strformat]

const hostsFilePath = "/etc/hosts"
  
proc getDataDir*(): Path =
  var path = Path("/var/cache/boxscanner")
  normalizePathEnd(path, true)
  path

proc wordlistDataDir*(): Path = 
  getDataDir() / Path("wordlists")

proc wordlistFilePath*(wordlistName: string): Path =
  wordlistDataDir() / Path(wordlistName)

proc nmapDataDir*(host: string): Path = 
  getDataDir() / Path(host) / Path("nmap")

proc nmapReportFilePath*(host: string): Path = 
  nmapDataDir(host) / Path("nmap_report.xml")

proc fuzzDataDir*(host: string): Path = 
  getDataDir() / Path(host) / Path("ffuf")

proc fuzzReportFilePath*(host: string, reportName: string): Path = 
  getDataDir() / Path(host) / Path("ffuf") / Path("ffuf_" & reportName & ".json")

proc initializeDataDirs*(host: string) =
   discard existsOrCreateDir(getDataDir())
   discard existsOrCreateDir(wordlistDataDir())
   discard existsOrCreateDir(getDataDir() / Path(host))
   discard existsOrCreateDir(nmapDataDir(host))
   discard existsOrCreateDir(fuzzDataDir(host))

proc updateHostsFile*(host: string, ip: string): void =
  ## Updates the host file entry for a host and ip.
  ## Creates an entry if it doesn't exist. 
  ## 
  ## For an entry like this: 1.1.1.1 a.b c.d, 
  ## calling updateHostsFile("a.b", "2.2.2.2") will update
  ## the entry to: 2.2.2.2 a.b c.d

  let hostsFile = open(hostsFilePath)
  defer: hostsFile.close()

  var buffer = ""
  var didReplacement = false
  for line in hostsFile.lines:
    let lineEntries = line.split(" ")
    if any(lineEntries, proc (x: string): bool = x == host):
      let tail = lineEntries[1..^1]
      buffer.add(fmt"{ip} " & join(tail, " ") & "\n")
      didReplacement = true
    else:
      buffer.add(line & "\n")

  if not didReplacement:
      buffer.add("# Entry created by boxscanner\n")
      buffer.add(fmt"{ip} {host}" & "\n\n")

  writeFile(hostsFilePath, buffer)

proc clearCache*(host: string): void =
  let pathToRemove = getDataDir() / Path(host)
  removeDir(pathToRemove)
