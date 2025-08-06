Clear-Host

function Mostrar-Menu {
    Write-Host ""
    Write-Host "======= MENÚ DE SCRIPTS ========" -ForegroundColor DarkGreen
    Write-Host "1. EN DESARROLLO"
    Write-Host "2. Analizador de Exes"
    Write-Host "3. EN DESAROLLO"
    Write-Host "4. EN DESAROLLO"
    Write-Host "0. Salir"
    Write-Host "===============================" -ForegroundColor DarkGreen
}

function Ejecutar-Script($url) {
    try {
        $tempPath = "$env:TEMP\temp_script_$(Get-Random).ps1"
        Invoke-WebRequest -Uri $url -OutFile $tempPath -UseBasicParsing
        Write-Host ""
        Write-Host "--- Ejecutando script ---" -ForegroundColor DarkBlue
        Write-Host ""

        . $tempPath

        Remove-Item $tempPath -Force
    }
    catch {
        Write-Host "`n✖ Fallo al usar script:`n$($_.Exception.Message)" -ForegroundColor DarkRed
    }
}

$seguir = $true

do {
    Mostrar-Menu
    $opcion = Read-Host "Selecciona una opción (0-4)"

    switch ($opcion) {
        '1' { Ejecutar-Script "" }
        '2' { Ejecutar-Script "https://raw.githubusercontent.com/OryzonSS/OryzonSS/refs/heads/main/Bamparser.ps1" }
        '3' { Ejecutar-Script "" }
        '4' { Ejecutar-Script "" }
        '0' {
            Write-Host "Saliendo, Adios!" -ForegroundColor DarkGreen
            $seguir = $false
        }
        default {
            Write-Host "Opción inválida. Intenta de nuevo." -ForegroundColor DarkRed
        }
    }

    if ($seguir) {
        Write-Host ""
        Write-Host "Pulsa Enter para seguir"
        [void][System.Console]::ReadLine()
    }

} while ($seguir)
