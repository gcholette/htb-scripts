import std/[strformat, osproc, json, syncio, sequtils, terminal, times, files, os, strutils, tables]
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
    filteredSize: int

type 
  FavorableConfigurations* = 
    seq[(FuzzConfiguration, ConfigurationFavorability)]

proc fuzzVhosts(config: FuzzConfiguration, wordlist: string): seq[string] =
  let (
    protocol, 
    host, 
    port, 
    filteredStatusCode, 
    filteredSize
  ) = (
    config.protocol, 
    config.host, 
    config.port, 
    config.filteredStatusCode, 
    config.filteredSize
  )

  let scanFileReportPath = fuzzReportFilePath(host, protocol, port, filteredStatusCode)
  let statusCodeArg = if filteredStatusCode == "": "" else: &"-fc {filteredStatusCode}"
  let sizeArg = if filteredSize == 0: "" else: &"-fs {filteredSize}"

  let command = fmt"ffuf -u {protocol}://{host}:{port} -w {wordlist} -H 'Host: FUZZ.{host}' -t 10 -p 0.2 {statusCodeArg} {sizeArg} -o {scanFileReportPath.string}"

  if fileExists(scanFileReportPath):
    removeFile(scanFileReportPath)

  let output = execProcess(command)

  if output.contains("errors occurred"):
    let err = output.splitLines()[0..2]
    for e in err:
      styledEcho(fgRed, e)
    raise newException(Exception, fmt"An error occured while running ffuf")

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

proc identifyFavorableSizeParameter*(configs: seq[FuzzConfiguration], maxResults: int): seq[int] =
  ## Read ffuf output files after the initial scans ran and see
  ## if we can find a size to filter by
  let maxResultsDelta = maxResults - 5
  var identifiedSizes: seq[int] = @[] 
  
  for config in configs:
    let (protocol, host, port, filteredStatusCode) = (config.protocol, config.host, config.port, config.filteredStatusCode)
    let scanFileReportPath = fuzzReportFilePath(host, protocol, port, filteredStatusCode)
    let reportStr = readFile(scanFileReportPath.string)
    let jsonContents = parseJson(reportStr)
    var foundLengths: seq[int] = @[]

    try:
      if jsonContents.kind == JObject:
        if jsonContents["results"].kind == JArray:
          let fuzzResults = jsonContents["results"].getElems()
          if fuzzResults.len >= maxResultsDelta:
            let value = fuzzResults.mapIt(it["length"].getInt())
            foundLengths.add(value)

    except Exception as e:
      styledEcho(fgRed, &"An error occured while parsing ffuf report {scanFileReportPath.string}")
      styledEcho(fgRed, e.msg)
    
    # counter and a for loop :sadface:
    var sizeCounter = initTable[int, int]()
    for x in foundLengths:
      sizeCounter[x] = sizeCounter.getOrDefault(x) + 1

    var maxSize: (int, int) = (0, 0)
    for k, v in sizeCounter:
      if v > maxSize[1]:
        maxSize = (k, v)

    if not any(identifiedSizes, proc (x: int): bool = x == maxSize[0]) and maxSize[0] != 0:
      identifiedSizes.add(maxSize[0])

  return identifiedSizes

proc determineFuzzParameters*(targetHost: string, ports: FingerprintedPorts): FavorableConfigurations =
  ## Todo - refactor this function
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

  var preliminaryFuzzResults: seq[seq[string]] = newSeq[seq[string]](configurations.len)

  ## Fuzz with initial configurations
  let startTime = epochTime()
  var m = createMaster()
  m.awaitAll:
    for i, config in configurations.pairs:
     m.spawn fuzzVhosts(config, wordlistFile.string) -> preliminaryFuzzResults[i]
  let endTime = epochTime()
  let duration = endTime - startTime
  echo "Done in ", duration, " seconds"

  ## Look for a size filter
  let sizeParameters = identifyFavorableSizeParameter(configurations, wordlistLines)

  var finalConfigurations: seq[FuzzConfiguration] = @[]
  for c in configurations:
    finalConfigurations.add(c)
    if sizeParameters.len > 0:
      var conf2 = c
      conf2.filteredSize = sizeParameters[0]
      finalConfigurations.add(conf2)

  echo &"Testing {finalConfigurations.len} configurations"
  var finalFuzzResults: seq[seq[string]] = newSeq[seq[string]](finalConfigurations.len)

  ## Re-fuzz with initial configurations
  let startTime2 = epochTime()
  var m2 = createMaster()
  m2.awaitAll:
    for i, config in finalConfigurations.pairs:
     m2.spawn fuzzVhosts(config, wordlistFile.string) -> finalFuzzResults[i]
  let endTime2 = epochTime()
  let duration2 = endTime2 - startTime2
  echo "Done in ", duration2, " seconds"
  
  var favorableResults: seq[(FuzzConfiguration, ConfigurationFavorability)] = @[]
  for i, x in finalFuzzResults.pairs:
    if x.len >= favorabilityDelta:
      favorableResults.add((finalConfigurations[i], cfNone))
    elif x.len > 0 and x.len < favorabilityDelta:
      favorableResults.add((finalConfigurations[i], cfExcellent))
    else:
      favorableResults.add((finalConfigurations[i], cfLikely))

  ## todo, select only some of the cfExcellent configurations 
  ## based on which has the highest amount of hits

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
  styledEcho(fgYellow, "No favorable configuration for fuzzing, skipping.")
  return @[]