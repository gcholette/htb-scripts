import std/osproc
import file_management

proc nmapScan*(host: string) = 
  let output = execProcess("nmap -sT -T4 -p- -Pn -oX " & nmapReportFilePath(host).string & " " & host)
  echo output

type
  HostStatus = enum 
    Up, Down

type 
  NmapReport = object
    hostStatus: HostStatus 
    openPorts: seq[int]

## wip
# proc parseNmapReport*(host: string): NmapReport =
#   NmapReport(
#     hostStatus: Up
#   )
#   if
#   let xmlFileContents