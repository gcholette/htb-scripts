import std/[envvars, dirs, paths, strutils, sequtils, strformat]

const hostsFilePath = "/etc/hosts"
  
proc getDataDir*(): Path =
  # var path = Path(getEnv("HOME")) / Path(".local") / Path("share") / Path("box_scanner")
  var path = Path("/tmp/box_scanner")
  normalizePathEnd(path, true)
  path

proc nmapDataDir*(host: string): Path = 
  getDataDir() / Path(host) / Path("nmap")

proc nmapReportFilePath*(host: string): Path = 
  nmapDataDir(host) / Path("nmap_report.xml")

proc initializeDataDirs*(host: string) =
   discard existsOrCreateDir(getDataDir())
   discard existsOrCreateDir(getDataDir() / Path(host))
   discard existsOrCreateDir(nmapDataDir(host))

proc checkHostfile*(host: string, ip: string): bool =
  let hostsFile = open(hostsFilePath)
  for line in hostsFile.lines:
    let lineEntries = line.split(" ")
    if any(lineEntries, proc (x: string): bool = x == host):
      hostsFile.close()
      return true

  hostsFile.close()
  return false

proc updateHostsFile*(host: string, ip: string): void =
  let hostsFile = open(hostsFilePath)
  var buffer = ""
  var didReplacement = false
  for line in hostsFile.lines:
    let lineEntries = line.split(" ")
    if any(lineEntries, proc (x: string): bool = x == host):
      buffer.add(fmt"{ip} {host}" & "\n")
      didReplacement = true
    else:
      buffer.add(line & "\n")

  if not didReplacement:
      buffer.add(fmt"{ip} {host}" & "\n")

  writeFile(hostsFilePath, buffer)
  hostsFile.close()
