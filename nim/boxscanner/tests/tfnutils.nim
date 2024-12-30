import std/[tables, unittest, sequtils]
import boxscanner/fnutils

test "uReduce works as expected":
  check @[1,2,3].uReduce(proc(acc: int, curr: int): int = acc + curr, 0) == 6
  check @[1,2,3].uReduce(proc(acc: seq[int], curr: int): seq[int] = concat(acc, @[curr + 1]), @[]) == @[2,3,4]

  proc reduceToOrderedTable(acc: OrderedTable[int, int], curr: int): OrderedTable[int, int] = 
    result = acc
    result[curr] = curr + 1

  check @[1,2,3].uReduce(reduceToOrderedTable, initOrderedTable[int, int]()) == 
    { 1: 2, 2: 3, 3: 4 }.toOrderedTable
