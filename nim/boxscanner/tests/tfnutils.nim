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

suite "Infix operators":
  test "|> works as expected with single arg functions":
    proc a(x: int): int = x + 1
    proc b(x: int): string = &"-{x}-"
    check 3 |> a == 4
    check 3 |> a |> b == "-4-"
    check 3 |> a |> b == 3.a.b

  test "|> works as expected with multi arg functions":
    proc a(x: int, y: int): int = x + y + 1
    proc b(x: int): int = x * 2 
    proc c(x: int, y:string, z: string, w: string): string = &"{y}{z}{w}{x}"
    check 0 |> c("**", "_", "~") == "**_~0"
    check 3 |> a(3) |> b |> c("**", "_", "~") == "**_~14"
    check 2 |> a(1) |> b |> c("**", "_", "~") == 2.a(1).b.c("**", "_", "~")
  