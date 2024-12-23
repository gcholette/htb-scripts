import std/osproc
import file_management

proc nmapScan*(host: string) = 
    let output = execProcess("nmap -sT -T4 -p- -Pn -oX " & nmapDataDir(host).string & "nmap_report.xml " & host)
    echo output
