import std/[streams, parsexml, strutils, osproc]
import file_management

proc nmapScan*(host: string) = 
  let output = execProcess("nmap -sT -T4 -p- -Pn -oX " & nmapReportFilePath(host).string & " " & host)
  echo output

type
  HostOSInfo* = object
    accuracy*: float
    name*: string

type
  HostStatus* = enum 
    Down, Up

type 
  NmapReport* = object
    hostStatus*: HostStatus 
    openPorts*: seq[int]
    scanStatus*: string
    osInfo*: HostOSInfo

## wip
proc parseNmapReport*(host: string): NmapReport =
  let filename = nmapReportFilePath(host)
  var s = newFileStream(filename.string, fmRead)
  if s == nil: quit("Opening the nmap report failed " & filename.string)

  var nmapReport = NmapReport()
  var x: XmlParser
  open(x, s, filename.string)

  proc nextElement() = 
    while x.kind != xmlElementOpen:
      x.next()

  proc enterElement() = 
      x.next()

  proc parsePorts() = 
    enterElement()
    while x.kind == xmlAttribute:
      if x.attrKey == "portid":
        let port = x.attrValue
        nmapReport.openPorts.add(parseInt(port))
      x.next()

  proc parseHostStatus() = 
    enterElement()
    nextElement()
    if x.kind == xmlElementOpen and x.elementName == "status":
      enterElement()
      while x.kind == xmlAttribute:
        if x.attrKey == "state":
          if x.attrValue == "up": nmapReport.hostStatus = Up
          else: nmapReport.hostStatus = Down
        x.next()

  proc parseScanStatus() = 
    enterElement()
    while x.kind == xmlAttribute:
      if x.attrKey == "exit":
        nmapReport.scanStatus = x.attrValue
      x.next()

  while x.kind != xmlEof:
    case x.kind:
      of xmlElementOpen:
        if x.elementName == "port":
          parsePorts()
        elif x.elementName == "host":
          parseHostStatus()
        # Scan Status
        elif x.elementName == "finished":
          parseScanStatus()
        else:
          x.next()
      of xmlEof: break
      else: x.next()

  x.close()
  nmapReport
