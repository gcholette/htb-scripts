import std/[tables, unittest]
import boxscanner/fingerprint

const input: FingerprintedPorts = toTable(
  [
    (22, FingerprintedPort(service: unknown)), 
    (80, FingerprintedPort(service: http)), 
    (443, FingerprintedPort(service: https)), 
    (3000, FingerprintedPort( service: http)),
    (8080, FingerprintedPort( service: unknown))
  ]
)

test "filterFingerprintedPorts works as expected":
  check filterFingerprintedPorts(input, https) == toTable([
    (443, FingerprintedPort(service: https))
  ])

  check filterFingerprintedPorts(input, http) == toTable([
    (80, FingerprintedPort(service: http)), 
    (3000, FingerprintedPort(service: http))
  ])

  check filterFingerprintedPorts(input, unknown) == toTable([
    (22, FingerprintedPort(service: unknown)),
    (8080, FingerprintedPort(service: unknown))
  ])

test "getPortsByService returns matching ports for a service":
  check getPortsByService(input, http) == @[3000, 80]
  check getPortsByService(input, https) == @[443]
  check getPortsByService(input, unknown) == @[22, 8080]
