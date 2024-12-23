from "std/cmdline" import paramStr, paramCount
from strformat import fmt 
from strutils import join, split
from sequtils import mapIt
from sugar import collect

proc main() = 
  if paramCount() < 1:
    echo "Usage: <source-latex-file>"
    quit(1)

  let 
    fileParam = paramStr(1)
    sourceFile = open(fileParam)

  let obfuscatedLatex = collect:
    for line in sourceFile.lines:
      if line.len != 0:
        "^^" & join(line.mapIt(fmt"{ord(it):X}"), "^^")
      else: ""
  
  echo join(obfuscatedLatex, "\n")
  sourceFile.close()

when isMainModule:
  main()
