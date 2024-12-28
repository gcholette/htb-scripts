import std/[strformat, osproc, json, syncio, sequtils, terminal, times, files, os, strutils, tables]
import malebolgia
import filemanagement, fingerprint

type
  FuzzConfiguration = object
    protocol: string
    host: string
    filteredStatusCode: string

proc fuzzVhosts(config: FuzzConfiguration, wordlist: string): seq[string] =
  let (protocol, host, filteredStatusCode) = (config.protocol, config.host, config.filteredStatusCode)

  let scanFileReportPath = fuzzReportFilePath(host, protocol, filteredStatusCode)
  let statusCodeArg = if filteredStatusCode == "": "" else: &"-fc {filteredStatusCode}"

  let command = fmt"ffuf -u {protocol}://{host} -w {wordlist} -H 'Host: FUZZ.{host}' -t 10 -p 0.2 {statusCodeArg} -o {scanFileReportPath.string}"

  if fileExists(scanFileReportPath):
    removeFile(scanFileReportPath)

  let output = execProcess(command)

  if output.contains("errors occurred"):
    let err = output.splitLines()[0..2]
    for e in err:
      styledEcho(fgRed, e)
    raise newException(Exception, fmt"An error occured while running ffuf")
  sleep(1000)

  let reportStr = readFile(scanFileReportPath.string)
  let jsonContents = parseJson(reportStr)

  try:
    if jsonContents.kind == JObject:
      if jsonContents["results"].kind == JArray:
        let fuzzResults = jsonContents["results"].getElems()
        if fuzzResults.len > 0:
          let value = fuzzResults.mapIt(it["host"].getStr())
          return value

    return @[]
  except Exception as e:
    styledEcho(fgRed, &"An error occured while parsing ffuf report {scanFileReportPath.string}")
    styledEcho(fgRed, e.msg)
    return @[]

proc determineFuzzParameters*(targetHost: string, ports: FingerprintedPorts): seq[int] =
  let protocols = ["http", "https"] 
  let filteredStatusCodes = ["", "200", "403", "301"] 
  var configurations: seq[FuzzConfiguration] = @[]
  let wordlistFile = wordlistFilePath("configuration-tester.txt").string

  for protocol in protocols: 
    for statusCode in filteredStatusCodes: 
      configurations.add(FuzzConfiguration( protocol: protocol, host: targetHost, filteredStatusCode: statusCode ))

  var fuzzResults: seq[seq[string]] = newSeq[seq[string]](configurations.len)
  let startTime = epochTime()

  var m = createMaster()
  m.awaitAll:
    for i, config in configurations.pairs:
     m.spawn fuzzVhosts(config, wordlistFile) -> fuzzResults[i]
  echo ""
  
  let endTime = epochTime()
  let duration = endTime - startTime
  echo "Done in ", duration, " seconds"

  for i, x in fuzzResults.pairs:
    echo fmt"{x.len} {configurations[i]}"

  return fuzzResults.mapIt(it.len)