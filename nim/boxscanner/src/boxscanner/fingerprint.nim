import std/[net, strutils, strformat, tables]
from puppy import fetch, Request, parseUrl

type 
  FingerprintedService* = enum 
    http, https, unknown

type
  FingerprintedPort* = object
    service*: FingerprintedService
  
type
  FingerprintedPorts* = Table[int, FingerprintedPort]

let f = { 1: FingerprintedService.http }.newTable

proc httpBannerGrab(host: string, port: int): bool =
  try:
    var socket = newSocket()
    defer: socket.close()
    socket.connect(host, Port(port))
    socket.send("HEAD / HTTP/1.1\r\nHost: " & host & "\r\n\r\n")
    
    let response = socket.recvLine()
    
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
      allowAnyHttpsCertificate: true
    ))
    return true
  except:
    return false

proc fingerprintPorts*(host: string, ports: seq[int]): FingerprintedPorts =
  var table = FingerprintedPorts() 
  for p in ports:
    let svc =
      if httpsBannerGrab(host, p):
        https
      elif httpBannerGrab(host, p):
        http
      else:
        unknown
    table[p] = FingerprintedPort(service: svc)

  return table

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
