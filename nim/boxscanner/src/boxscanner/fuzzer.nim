import std/[strformat, osproc, json, syncio, sequtils, terminal, times, files, strutils, tables, paths]
import malebolgia
import filemanagement, fingerprint, wordlists, fnutils

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
    
    let sizeCounter = foundLengths.uFold(
      func(acc: var Table[int, int], curr: int) = 
        acc[curr] = acc.getOrDefault(curr) + 1, 
      initTable[int, int]()
    )

    let maxSize = sizeCounter.pairs.toSeq.uFold(
      func(acc: (int, int), curr: (int, int)): (int, int) = 
        if curr[1] > acc[1]: return curr
        else: return acc,
      (0, 0)
    )

    if not any(
        identifiedSizes, 
        proc (x: int): bool = x == maxSize[0]
      ) and maxSize[0] != 0:
      identifiedSizes.add(maxSize[0])

  return identifiedSizes

proc fuzzVhostsConfigurations(
  configurations: seq[FuzzConfiguration], 
  wordlistFile: Path
): seq[(Fuzzconfiguration, int)] =
  var finalFuzzResults: seq[seq[string]] = newSeq[seq[string]](configurations.len)
  var m = createMaster()

  let startTime = epochTime()
  m.awaitAll:
    for i, config in configurations.pairs:
     m.spawn fuzzVhosts(config, wordlistFile.string) -> finalFuzzResults[i]

  let endTime = epochTime()
  echo "Done in ", endTime - startTime, " seconds"

  for i, r in finalFuzzResults.pairs:
    result.add((configurations[i], r.len))

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
    echo &"Fuzzing vhosts with {likelyConfigurations.len} somewhat favorable configuration(s)..."
    return batchFuzzVhosts(likelyConfigurations)
  
  # Don't run cfNone configurations as they will just waste time.
  styledEcho(fgYellow, "No favorable configuration for fuzzing, skipping.")
  return @[]

proc getPreliminaryConfigurations(
  targetHost: string, 
  ports: FingerprintedPorts
): seq[FuzzConfiguration] =
  let filteredStatusCodes = ["", "200", "403", "301", "302"] 
  let httpPorts = getPortsByService(ports, http)
  let httpsPorts = getPortsByService(ports, https)

  for p in httpPorts: 
    for statusCode in filteredStatusCodes: 
      result.add(FuzzConfiguration( protocol: "http", host: targetHost, port: p, filteredStatusCode: statusCode ))

  for p in httpsPorts: 
    for statusCode in filteredStatusCodes: 
      result.add(FuzzConfiguration( protocol: "https", host: targetHost, port: p, filteredStatusCode: statusCode ))

proc updateConfigurationWithSizes(
  configurations: seq[FuzzConfiguration], 
  sizeParameters: seq[int]
): seq[FuzzConfiguration] =
  for c in configurations:
    result.add(c)
    if sizeParameters.len > 0:
      var conf2 = c
      conf2.filteredSize = sizeParameters[0]
      result.add(conf2)

proc determineFuzzParameters*(
  targetHost: string, 
  ports: FingerprintedPorts
): FavorableConfigurations =
  let wordlistFile = wordlistFilePath("configuration-tester.txt")
  let wordlistLines = countWordlistLines(wordlistFile)
  let preliminaryConfigurations = getPreliminaryConfigurations(targetHost, ports)
  let favorabilityDelta = wordlistLines - 10 

  echo &"Testing {preliminaryConfigurations.len} preliminary configurations"

  # Run it a first time to generate json reports
  discard fuzzVhostsConfigurations(preliminaryConfigurations, wordlistFile)

  ## Look for a size filter in those json reports
  let sizeParameters = 
    identifyFavorableSizeParameter(preliminaryConfigurations, wordlistLines)

  let finalConfigurations: seq[FuzzConfiguration] = 
    updateConfigurationWithSizes(preliminaryConfigurations, sizeParameters)

  echo &"Testing {finalConfigurations.len} configurations"
  let finalFuzzResults = fuzzVhostsConfigurations(finalConfigurations, wordlistFile)
  
  var favorableResults: seq[(FuzzConfiguration, ConfigurationFavorability)] = @[]
  for (conf, hits) in finalFuzzResults:
    if hits >= favorabilityDelta:
      favorableResults.add((conf, cfNone))
    elif hits > 0 and hits < favorabilityDelta:
      favorableResults.add((conf, cfExcellent))
    else:
      favorableResults.add((conf, cfLikely))
  
  let noneConfigurations = favorableResults.filterIt(it[1] == cfNone).mapIt(it[0])
  let likelyConfigurations = favorableResults.filterIt(it[1] == cfLikely).mapIt(it[0])
  let excellentConfigurations = favorableResults.filterIt(it[1] == cfExcellent).mapIt(it[0])

  if excellentConfigurations.len > 0:
    styledEcho(fgGreen, &"Identified {excellentConfigurations.len} very favorable configurations")
    for c in excellentConfigurations:
      echo &"- port: {c.port}, proto: {c.protocol}, code: {c.filteredStatusCode}, size: {c.filteredSize}"
  elif excellentConfigurations.len == 0:
    styledEcho(fgYellow, &"Identified {excellentConfigurations.len} very favorable configurations")
    if likelyConfigurations.len > 0:
      styledEcho(fgYellow, &"Identified {likelyConfigurations.len} somewhat favorable configurations")
    elif noneConfigurations.len > 0:
      styledEcho(fgYellow, &"Identified {noneConfigurations.len} bad configurations")

  ## todo, select only some of the cfExcellent configurations 
  ## based on which has the highest amount of hits

  return favorableResults
