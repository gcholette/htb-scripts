import std/sugar

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
  