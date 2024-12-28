import std/[asyncdispatch, files, httpclient, syncio, strformat, sequtils, asyncfutures, paths]
import filemanagement

const wordlistHttpPath = "https://raw.githubusercontent.com/gcholette/htb-scripts/refs/heads/main/wordlists/"

proc downloadWordlist(wordlistName: string): Future[void] {.async.} =
  let wordlistUrl = wordlistHttpPath & wordlistName
  let localWordlistPath = wordlistFilePath(wordlistName)
  if not fileExists(localWordlistPath):
    let client = newAsyncHttpClient()
    defer: client.close()

    let response = await client.get(wordlistUrl)
    if response.code() != HttpCode(200):
        raise newException(ValueError, fmt"Failed to download wordlist: {wordlistName}, HTTP Status: {response.status}")

    let outputFile = open(localWordlistPath.string, FileMode.fmWrite)
    defer: outputFile.close()

    while true:
      let (ok, data) = await response.bodyStream.read()
      if not ok: break
      outputFile.write(data)

proc setupWordlists*(): void =
  let tasks = [
    "subdomains-large.txt",
    "subdomains-small.txt",
    "dummy-test.txt",
    "configuration-tester.txt",
    "top-htb-vhosts.txt",
  ].mapIt(downloadWordlist(it))
  waitFor all tasks

proc countWordlistLines*(wordlistPath: Path): int =
  ## Todo - optimise this if ever really needed on big wordlists
  var count = 0
  for line in lines(wordlistPath.string):
    count.inc()
  return count
