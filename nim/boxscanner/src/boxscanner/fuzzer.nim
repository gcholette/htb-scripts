import std/[strformat, osproc, json, syncio, sequtils, terminal, times, files, os, strutils]
import malebolgia
import filemanagement, fingerprint, wordlists

type
  ConfigurationFavorability = enum
    cfNone, cfLikely, cfExcellent

type
  FuzzConfiguration = object
    protocol: string
    host: string
    port: int
    filteredStatusCode: string

type 
  FavorableConfigurations* = 
    seq[(FuzzConfiguration, ConfigurationFavorability)]

proc fuzzVhosts(config: FuzzConfiguration, wordlist: string): seq[string] =
  let (protocol, host, port, filteredStatusCode) = (config.protocol, config.host, config.port, config.filteredStatusCode)

  let scanFileReportPath = fuzzReportFilePath(host, protocol, port, filteredStatusCode)
  let statusCodeArg = if filteredStatusCode == "": "" else: &"-fc {filteredStatusCode}"

  let command = fmt"ffuf -u {protocol}://{host}:{port} -w {wordlist} -H 'Host: FUZZ.{host}' -t 10 -p 0.2 {statusCodeArg} -o {scanFileReportPath.string}"

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

proc determineFuzzParameters*(targetHost: string, ports: FingerprintedPorts): FavorableConfigurations =
  let filteredStatusCodes = ["", "200", "403", "301", "302"] 
  let httpPorts = getPortsByService(ports, http)
  let httpsPorts = getPortsByService(ports, https)
  let wordlistFile = wordlistFilePath("configuration-tester.txt")
  let wordlistLines = countWordlistLines(wordlistFile)
  let favorabilityDelta = wordlistLines - 10 

  var configurations: seq[FuzzConfiguration] = @[]

  for p in httpPorts: 
    for statusCode in filteredStatusCodes: 
      configurations.add(FuzzConfiguration( protocol: "http", host: targetHost, port: p, filteredStatusCode: statusCode ))

  for p in httpsPorts: 
    for statusCode in filteredStatusCodes: 
      configurations.add(FuzzConfiguration( protocol: "https", host: targetHost, port: p, filteredStatusCode: statusCode ))

  echo &"Testing {configurations.len} configurations"

  var fuzzResults: seq[seq[string]] = newSeq[seq[string]](configurations.len)
  let startTime = epochTime()

  var m = createMaster()
  m.awaitAll:
    for i, config in configurations.pairs:
     m.spawn fuzzVhosts(config, wordlistFile.string) -> fuzzResults[i]
  
  var favorableResults: seq[(FuzzConfiguration, ConfigurationFavorability)] = @[]
  for i, x in fuzzResults.pairs:
    if x.len >= favorabilityDelta:
      favorableResults.add((configurations[i], cfNone))
    elif x.len > 0 and x.len < favorabilityDelta:
      favorableResults.add((configurations[i], cfExcellent))
    else:
      favorableResults.add((configurations[i], cfLikely))

  let endTime = epochTime()
  let duration = endTime - startTime
  echo "Done in ", duration, " seconds"

  return favorableResults

proc batchFuzzVhosts(configurations: seq[FuzzConfiguration]): seq[string] =
  let wordlistFile = wordlistFilePath("subdomains-small.txt")
  var fuzzResults: seq[seq[string]] = newSeq[seq[string]](configurations.len)

  let startTime = epochTime()
  var m = createMaster()
  m.awaitAll:
    for i, config in configurations.pairs:
      m.spawn fuzzVhosts(config, wordlistFile.string) -> fuzzResults[i]

  let endTime = epochTime()
  let duration = endTime - startTime
  echo "Done in ", duration, " seconds"

  var allResults: seq[string] = @[]
  for rs in fuzzResults:
    for r in rs:
      allResults.add(r)

  return deduplicate[string](allResults) 

proc fuzzVhostsByConfigurationFavorability*(favorableConfigurations: FavorableConfigurations): seq[string] =
  let likelyConfigurations = favorableConfigurations.filterIt(it[1] == cfLikely).mapIt(it[0])
  let excellentConfigurations = favorableConfigurations.filterIt(it[1] == cfExcellent).mapIt(it[0])

  # If a excellent configuration is found, run only that
  if excellentConfigurations.len > 0:
    echo &"Fuzzing vhosts with {excellentConfigurations.len} very favorable configuration(s)..."
    return batchFuzzVhosts(excellentConfigurations)

  # If no excellent config is found, run likely configurations
  elif likelyConfigurations.len > 0:
    echo &"Fuzzing vhosts with {likelyConfigurations.len} very favorable configuration(s)..."
    return batchFuzzVhosts(likelyConfigurations)
  
  # Don't run cfNone configurations as they will just waste time.
  return @[]