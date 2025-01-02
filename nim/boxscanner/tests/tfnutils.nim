import std/[tables, unittest, sequtils, sugar, strformat]
import boxscanner/fnutils

suite "uFold":
  test "works with simple reduce operations":
    check @[1,2,3].uFold((x: int, y) => x + y, 0) == 6
    check @[1,2,3].uFold((x: seq[int], y) => concat(x, @[y + 1]), @[]) == @[2,3,4]
  
  test "list2table with reassignment":
    check @[1,2,3].uFold(
      proc (acc: OrderedTable[int, int], curr: int): OrderedTable[int, int] = 
        result = acc
        result[curr] = curr + 1,
      initOrderedTable[int, int]()
    ) == { 1: 2, 2: 3, 3: 4 }.toOrderedTable

  test "list2table with mutation":
    check @[1,2,3].uFold(
      proc (acc: var OrderedTable[int, int], curr: int) = 
        acc[curr] = curr + 1,
      initOrderedTable[int, int]()
    ) == { 1: 2, 2: 3, 3: 4 }.toOrderedTable
