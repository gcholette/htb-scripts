from std/envvars import getEnv
import std/dirs
import std/paths
  
proc getDataDir*(): Path =
  when defined(windows):
    result = Path(getEnv("APPDATA")) / Path("box_scanner")
  else:
    result = Path(getEnv("HOME")) / Path(".local") / Path("share") / Path("box_scanner")
  normalizePathEnd(result, true)

proc nmapDataDir*(host: string): Path = 
  getDataDir() / Path(host) / Path("nmap")

proc nmapReportFilePath*(host: string): Path = 
  nmapDataDir(host) / Path("nmap_report.xml")

proc initializeDataDirs*(host: string) =
   discard existsOrCreateDir(getDataDir())
   discard existsOrCreateDir(getDataDir() / Path(host))
   discard existsOrCreateDir(nmapDataDir(host))
