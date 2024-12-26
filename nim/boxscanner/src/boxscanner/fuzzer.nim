import std/[asyncdispatch, strformat, osproc]
import filemanagement

proc fuzzSubdomains(protocol: string, targetHost: string, wordlist: string,) =
  let path = fuzzReportFilePath(targetHost, protocol)
  discard execProcess(fmt"ffuf -u {protocol}://{targetHost} -w {wordlist} -H 'Host: FUZZ.{targetHost}' -fc 200 -o {path}")

proc preliminaryFuzzScans() =
  echo "dummy"