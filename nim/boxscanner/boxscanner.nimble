# Package

version       = "0.1.0"
author        = "gcholette"
description   = "Scanner for HTB Boxes"
license       = "MIT"
srcDir        = "src"
installExt    = @["nim"]
bin           = @["boxscanner"]


# Dependencies

requires "nim >= 2.2.0"
requires "malebolgia == 1.3.2"

task docs, "Generates documentation":
  exec "nim doc --project --index:on --outdir:htmldocs ./src/**.nim"
