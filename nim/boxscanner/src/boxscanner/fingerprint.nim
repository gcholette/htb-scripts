import std/[net, strutils, strformat, tables, terminal]
from puppy import fetch, head, Request, parseUrl

const timeoutLimitMs = 2000
const timeoutLimitSec = 2

type 
  FingerprintedService* = enum 
    http, https, unknown

type
  FingerprintedPort* = object
    service*: FingerprintedService
  
type
  FingerprintedPorts* = OrderedTable[int, FingerprintedPort]

proc httpBannerGrab(host: string, port: int): bool =
  try:
    var socket = newSocket()
    defer: socket.close()
    socket.connect(host, Port(port), timeoutLimitMs)
    socket.send("GET / HTTP/1.1\r\nHost: " & host & "\r\n\r\n")
    let response = socket.recv(10, timeoutLimitMs)

    return response.startsWith("HTTP/")
  except:
    return false

proc httpsBannerGrab(host: string, port: int): bool =
  ## Tries to connect over SSL with HTTPS protocol.
  ## If the connection establishes, it assumes that
  ## the endpoint supports HTTPS.
  ## 
  ## Using puppy here since std library has an issue
  ## with verifyMode = CVerifyNone
  try:
    discard fetch(Request(          
      url: parseUrl(&"https://{host}:{port}"),
      verb: "get",
      allowAnyHttpsCertificate: true,
      timeout: timeoutLimitSec
    ))
    return true
  except:
    return false

proc fingerprintPort*(host: string, port: int): FingerprintedService =
  ## For the current purpose of boxscanner, just checking for http or https 
  ## servers is enough
  if httpBannerGrab(host, port):
    http
  elif httpsBannerGrab(host, port):
    https
  else:
    unknown

proc fingerprintPorts*(host: string, ports: seq[int]): FingerprintedPorts =
  for p in ports:
    styledEcho(styleDim, &"Fingerprinting {p}...")
    let svc = fingerprintPort(host, p) 
    result[p] = FingerprintedPort(service: svc)

proc filterFingerprintedPorts*(ports: FingerprintedPorts, filterBy: FingerprintedService): FingerprintedPorts =
  var filteredTable = FingerprintedPorts()
  for k, v in ports:
    if v.service == filterBy:
      filteredTable[k] = v
  return filteredTable

proc getPortsByService*(ports: FingerprintedPorts, filterBy: FingerprintedService): seq[int] =
  let filteredPorts = filterFingerprintedPorts(ports, filterBy)
  var acc: seq[int] = @[]
  for k in filteredPorts.keys:
    acc.add(k)
  return acc
