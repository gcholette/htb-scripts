import std/sugar

proc uReduce*[T, Y](input: seq[Y], fn: ((T, Y) {.closure.} -> T), first: T): T =
  ## Does a for loop since tail call recursion is not garanteed in nim.
  result = first
  for x in input:
    result = fn(result, x)
