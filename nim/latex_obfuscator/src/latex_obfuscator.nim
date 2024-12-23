from std/cmdline import paramStr, paramCount
from strformat import fmt 
from strutils import join, split
from sequtils import mapIt
from sugar import collect

proc obfuscateLatexFromFile*(sourceFilePath: string): string =
  ## Reads a LaTeX file, obfuscates it by converting every character 
  ## to its hexadecimal representation, and outputs the result.
  ## Useful for bypassing filters.
  ## 
  ## For instance, \write18 becomes ^^5C^^77^^72^^69^^74^^65^^31^^38,
  ## this is completely valid LaTeX.

  let sourceFile = open(sourceFilePath)
  let obfuscatedLatex = collect:
    for line in sourceFile.lines:
      if line.len != 0:
        "^^" & join(line.mapIt(fmt"{ord(it):X}"), "^^")
      else: ""

  sourceFile.close()
  join(obfuscatedLatex, "\n")

when isMainModule:
  if paramCount() < 1:
    echo "Usage: <source-latex-file>"
    quit(1)

  let fileParam = paramStr(1)

  echo obfuscateLatexFromFile fileParam
