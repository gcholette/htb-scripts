import std/[strformat, osproc, json, syncio, sequtils, terminal, times]
import malebolgia
import filemanagement

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
  discard execProcess(command)

  let reportStr = readFile(scanFileReportPath.string)
  let jsonContents = parseJson(reportStr)

  try:
    if jsonContents.kind == JObject:
      if jsonContents["results"].kind == JArray:
        let fuzzResults = jsonContents["results"].getElems()
        if fuzzResults.len > 0:
          stdout.write("+")
          let value = fuzzResults.mapIt(it["host"].getStr())
          return value

    stdout.write("-")
    return @[]
  except Exception as e:
    styledEcho(fgRed, &"An error occured while parsing ffuf report {scanFileReportPath.string}")
    styledEcho(fgRed, e.msg)
    stdout.write("x")
    return @[]

proc preliminaryFuzzScans*(targetHost: string): seq[int] =
  let protocols = ["http", "https"] 
  let filteredStatusCodes = ["", "200", "403", "301"] 
  var configurations: seq[FuzzConfiguration] = @[]
  let wordlistFile = wordlistFilePath("dummy-test.txt").string

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

  return fuzzResults.mapIt(it.len)