# Package
version       = "0.1.1"
author        = "gcholette"
description   = "Basic latex obfuscation"
license       = "MIT"
srcDir        = "src"
bin           = @["latex_obfuscator"]

# Dependencies
requires "nim >= 2.2.0"

task docs, "Generates documentation":
  exec "nim doc --project --index:on --outdir:htmldocs ./src/**.nim"
