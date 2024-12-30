import std/[macros, sugar]

##
## Some general FP utilities
##

proc uFold*[Acc, Cur](
  input: seq[Cur], 
  fn: ((Acc, Cur) {.closure.} -> Acc), 
  first: Acc
): Acc =
  ## Pure fold function, takes a fn parameter that returns the new value
  ## for the accumulator.
  runnableExamples:
    let list = @[1, 2, 3, 4]
    let res = uFold(list, proc(x: int, y:int): int = x + y, 0)
    assert res == 10

  result = first
  for x in input:
    result = fn(result, x)

proc uFold*[Acc, Cur](
  input: seq[Cur], 
  fn: ((acc: var Acc, Cur) {.closure.} -> void), 
  first: Acc
): Acc =
  ## Impure fold function, the fn parameter will mutate the accumulator 
  ## directly. This is for performance and conciseness purposes.
  runnableExamples:
    import std/tables
    let list = @[1, 2, 3]
    let res = uFold(
      list,
      proc (acc: var OrderedTable[int, int], curr: int) = 
        acc[curr] = curr + 1,
      initOrderedTable[int, int]()
    )
    assert res == { 1: 2, 2: 3, 3: 4 }.toOrderedTable

  result = first
  for x in input:
    fn(result, x)

macro `|>`*(lhs, rhs: untyped): untyped =
  ## Pipe operator, inserts the piped argument as the first arg of
  ## the piped functions. Still doesn't work with newlines with
  ## correct indentation tough.
  runnableExamples:
    import std/strformat
    proc fn1(x: int): int = x - 1
    proc fn2(x: int, y: string, z: string): string = fmt"{x}{y}{z}"

    assert 1 |> fn1 |> fn2("_", "-") == "0_-"

  case rhs.kind:
  of nnkIdent:
    result = newCall(rhs, lhs)
  else:
    result = rhs
    result.insert(1, lhs)