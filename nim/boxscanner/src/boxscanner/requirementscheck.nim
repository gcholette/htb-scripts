import std/[osproc, strutils]

proc requirementsMsg(): void = 
  echo "This program requires other binaries to be installed on the host."
  echo "Namely: "
  echo " - nmap"
  echo " - ffuf"
  echo " - cewl"
  echo ""

proc checkNmapInstall(): void =
  let output = execProcess("nmap -h")
  if not output.startsWith("Nmap") or output.contains(", did you mean"):
    requirementsMsg()
    quit("nmap is not installed", 1)

proc checkFfufInstall(): void =
  let output = execProcess("ffuf -h")
  if not output.contains("Fuzz Faster U Fool") or output.contains(", did you mean"):
    requirementsMsg()
    quit("ffuf is not installed", 1)

proc checkCewlInstall(): void =
  let output = execProcess("cewl -h")
  if not output.contains("CeWL") or output.contains(", did you mean"):
    requirementsMsg()
    quit("cewl is not installed", 1)

proc checkRequirements*(): void =
  checkNmapInstall()
  checkFfufInstall()
  checkCewlInstall()
