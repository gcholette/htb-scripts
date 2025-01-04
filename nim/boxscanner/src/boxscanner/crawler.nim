import std/[strformat, terminal]
import fingerprint
from puppy import fetch, get, Request, parseUrl

type
  CrawlStatus = enum 
    success, failure

type
  CrawlPageResult = object
    status: CrawlStatus
    contents: string

proc firstLevelCrawl*(host: string, port: int): CrawlPageResult =
  try:
    let svc = fingerprintPort(host,  port)
    case svc:
      of http:
        let response = get(&"http://{host}:{port}")
        return CrawlPageResult(status: success, contents: response.body)
      of https:
        let response = fetch(Request(          
          url: parseUrl(&"https://{host}:{port}"),
          verb: "get",
          allowAnyHttpsCertificate: true
        ))
        return CrawlPageResult(status: success, contents: response.body)
      else:
        return CrawlPageResult(status: failure, contents: "")

  except:
    styledEcho(fgRed, &"Could not crawl {host}:{port}")
    return CrawlPageResult(status: failure, contents: "")

