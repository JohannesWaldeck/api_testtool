# =============================== #
# PowerShell Script: GET/POST
# =============================== #
$global:lineCounter = 1
$allowedCookies = @('sap-XSRF_WC1_100', 'sap-usercontext')
$postData = @{ '' = '' } | ConvertTo-Json

# ==========================================================
# 📁 LOG FOLDER INITIALIZATION (MUST RUN FIRST)
# ==========================================================
$scriptRoot = $PSScriptRoot
if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }

$global:logFolder = Join-Path -Path $scriptRoot -ChildPath "logs"
if (-not (Test-Path $global:logFolder)) { New-Item -Path $global:logFolder -ItemType Directory | Out-Null }

# =============================== #
# Funktionen
# =============================== #

function Clear-Screen { Clear-Host }

function Resolve-Auth {
    param ([object]$request, [object]$collection)
    $authObj = if ($request.request.auth -and $request.request.auth.type -ne "inherit") { $request.request.auth } else { $collection.auth }
    if (-not $authObj) { return @{} }
    switch ($authObj.type) {
        "basic" {
            $username = $authObj.basic.username
            $password = $authObj.basic.password
            $base64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${username}:${password}"))
            return @{ 'Authorization' = "Basic $base64Auth" }
        }
        "oauth2" { return @{ 'Authorization' = "Bearer $($authObj.oauth2.accessToken)" } }
        default { return @{} }
    }
}

function Log-Message {
    param (
        [string]$message,
        [ValidateSet("Default","Red","Green","Yellow","Cyan","Magenta","Blue","White")]
        [string]$Color = "Default",
        [switch]$NoLog
    )

    $lineNum = $global:lineCounter.ToString("D3")
    $numberedMessage = "<Line Nr. $lineNum> $message"

    if ($Color -eq "Default") {
        Write-Host $numberedMessage
    } else {
        Write-Host $numberedMessage -ForegroundColor $Color
    }

    if (-not $NoLog) {
        $numberedMessage | Out-File -Append -FilePath $global:LogFile
    }

    $global:lineCounter++
}

function Write-Section {
    param (
        [string]$Title,
        [switch]$NoLog
    )
    Log-Message "----- $Title -----" -Color Cyan
}

function Write-BlockBoundary {
    param (
        [string]$Title,
        [switch]$NoLog
    )
    Log-Message "==== $Title ====" -Color Cyan
}

function Write-Request-Header {
    param (
        [Parameter(Mandatory)]
        [string]$RequestName
    )

    Write-BlockBoundary "REQUEST: $RequestName"
}

function Log-Critical {
    param (
        [string]$message,
        [switch]$NoLog
    )

    if ($NoLog) { return }

    $lineNum = $global:lineCounter.ToString("D3")
    "$message" | Out-File -Append -FilePath $global:LogFile
    $global:lineCounter++
}


function Log-Only {
    param (
        [Parameter(Mandatory)]
        [string]$Message
    )

    $lineNum = $global:lineCounter.ToString("D3")
    "<Line Nr. $lineNum> $Message" | Out-File -Append -FilePath $global:LogFile
    $global:lineCounter++
}


function Select-PostmanCollection {
    param (
        [string]$folderPath = $PSScriptRoot
    )

    # UI only — do NOT log
    Write-Section "Postman Collection Selection" -NoLog

    $postmanFiles = Get-ChildItem -Path $folderPath -Filter "*.json"

    if ($postmanFiles.Count -eq 0) {
        Log-Message "No .json files found in $folderPath." -Color Red
        return $null
    }

    for ($i = 0; $i -lt $postmanFiles.Count; $i++) {
        $fullPath = $postmanFiles[$i].FullName
        $dir = Split-Path $fullPath -Parent
        $file = Split-Path $fullPath -Leaf
        Write-Host "$dir\" -NoNewline
        Write-Host $file -ForegroundColor Yellow
    }

    $selection = Show-InteractiveFileSelection -files $postmanFiles

    if (-not $selection) {
        Log-Message "No file selected." -Color Red
        return $null
    }

    $selectedFile = $postmanFiles | Where-Object { $_.Name -eq $selection }

    if (-not $selectedFile) {
        Log-Message "Invalid file selection." -Color Red
        return $null
    }

    # ✅ the ONLY thing logged from this function
    Log-Message "Selected file: $($selectedFile.FullName)"
    return $selectedFile.FullName
}


# -----------------------------
# Compact TCP check (returns OK/FAIL for metrics)
# -----------------------------
# -----------------------------
# TCP functions (unchanged, safe)
# -----------------------------
function Test-TCPConnection-Compact {
    param ([string]$url)
    try {
        $uri = [System.Uri]$url
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect($uri.Host, $uri.Port)
        if ($tcp.Connected) { 
            $tcp.Close()
            return "OK"
        }
    } catch {
        return "FAIL"
    }
}

function Test-TCPConnection {
    param ([string]$url)

    try {
        $uri = [System.Uri]$url
        Write-Section "Testing TCP Connection"
        Log-Message "Testing TCP Connection to: $($uri.Host) on port $($uri.Port)"

        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect($uri.Host, $uri.Port)
        if ($tcp.Connected) {
            Log-Message "Connection to $($uri.Host) on port $($uri.Port) succeeded." -Color Green
            $tcp.Close()
        }
    } catch {
        Write-Section "TCP Connection Failed"
        Log-Message "Connection Failed" -Color Red
        Log-Message "Error: $($_.Exception.Message)" -Color Red
    }
}


function Show-ParsedUrl {
    param (
        [string]$method,
        [string]$url
    )

    $uri = [System.Uri]$url
    Write-Section "Parsed Request"
    Log-Message "method: $method"
    Log-Message "protocol: $($uri.Scheme)"
    Log-Message "domain: $($uri.Host)"
    Log-Message "resource: $($uri.AbsolutePath)"

    if ($uri.Query) {
        Log-Message "parameters:"
        foreach ($pair in $uri.Query.TrimStart('?').Split('&')) {
            $kv = $pair.Split('=', 2)
            $key = [System.Web.HttpUtility]::UrlDecode($kv[0])
            $val = if ($kv.Count -gt 1) { [System.Web.HttpUtility]::UrlDecode($kv[1]) } else { "" }
            Log-Message "---${key}: ${val}"
        }
    } else {
        Log-Message "parameters: none"
    }
}


function Show-Response {
    param ([hashtable]$Result)

    $response = $Result.Response
    Write-Section "Response Summary"
    Log-Message "HTTP Status: $($Result.Status)"
    Log-Message "Duration: $($Result.TimeMs) ms"
    Log-Message "TCP: $($Result.Tcp)"

    if (-not $response) {
        Write-Section "Response"
        Log-Message "No HTTP response received"
        return
    }

    Write-Section "Response Headers"
    foreach ($k in ($response.Headers.Keys | Sort-Object)) {
        Log-Message ("{0}: {1}" -f $k, $response.Headers[$k])
    }

    Write-Section "Response Cookies"
    $cookies = Parse-ResponseCookies -Response $response
    if ($cookies.Count -eq 0) {
        Log-Message "No cookies returned"
    } else {
        foreach ($c in $cookies) {
            Log-Message "$($c.Name) = $($c.Value)"
        }
    }

    Write-Section "Response Body"
    if ($response.Content -and $response.Content.Trim() -ne "") {
        try {
            $pretty = ($response.Content | ConvertFrom-Json | ConvertTo-Json -Depth 10)
            foreach ($line in $pretty -split "`n") { Log-Message $line }
        } catch {
            foreach ($line in $response.Content -split "`n") { Log-Message $line }
        }
    } else {
        Log-Message "(empty body)"
    }
}


# -----------------------------
# Parse cookies helper
# -----------------------------
function Parse-ResponseCookies {
    param ([Microsoft.PowerShell.Commands.WebResponseObject]$Response)

    $cookies = @()
    if ($Response.Headers['Set-Cookie']) {
        foreach ($line in $Response.Headers.GetValues('Set-Cookie')) {
            $parts = $line.Split(';')
            $nv = $parts[0].Split('=', 2)
            $cookies += [PSCustomObject]@{
                Name = $nv[0]
                Value = if ($nv.Count -gt 1) { $nv[1] } else { "" }
                Raw = $line
            }
        }
    }
    return $cookies
}


function Show-Request {
    param (
        [string]$method,
        [string]$url,
        [hashtable]$headers,
        [string]$body = "",
        [switch]$previewOnly,
        [switch]$NoLog
    )

    if (-not $previewOnly) {
        Write-Section "Parsed Request" -NoLog:$NoLog
        Log-Message "full-url: $url" -NoLog:$NoLog
        Log-Message "method: $method" -NoLog:$NoLog

        $uri = [System.Uri]$url
        Log-Message "protocol: $($uri.Scheme)" -NoLog:$NoLog
        Log-Message "domain: $($uri.Host)" -NoLog:$NoLog
        Log-Message "resource: $($uri.AbsolutePath)" -NoLog:$NoLog

        if ($uri.Query) {
            Log-Message "parameters:" -NoLog:$NoLog
            foreach ($pair in $uri.Query.TrimStart('?').Split('&')) {
                $kv = $pair.Split('=', 2)
                $key = [System.Web.HttpUtility]::UrlDecode($kv[0])
                $val = if ($kv.Count -gt 1) { [System.Web.HttpUtility]::UrlDecode($kv[1]) } else { "" }
                Log-Message "---${key}: ${val}" -NoLog:$NoLog
            }
        } else {
            Log-Message "parameters: none" -NoLog:$NoLog
        }
    }

    Write-Section "Request Headers" -NoLog:$NoLog
    if ($headers.Count -eq 0) {
        Log-Message "(no headers)" -NoLog:$NoLog
    } else {
        foreach ($key in ($headers.Keys | Sort-Object)) {
            $val = $headers[$key]
            if ($key -match 'authorization|cookie') { $val = "******" }
            Log-Message "${key}: ${val}" -NoLog:$NoLog
        }
    }

    Write-Section "Request Body" -NoLog:$NoLog
    if ($body -and $body.Trim() -ne "") {
        try {
            $pretty = ($body | ConvertFrom-Json | ConvertTo-Json -Depth 10)
            foreach ($line in $pretty -split "`n") { Log-Message $line -NoLog:$NoLog }
        } catch {
            foreach ($line in $body -split "`n") { Log-Message $line -NoLog:$NoLog }
        }
    } else {
        Log-Message "not supplied" -NoLog:$NoLog
    }
}


# ==========================
# PRINT-TREE FUNCTION
# ==========================
function Print-Tree {
    param (
        [array]$items,
        [string]$prefix = "",
        [switch]$NoLog
    )

    for ($i = 0; $i -lt $items.Count; $i++) {
        $item = $items[$i]
        $last = ($i -eq $items.Count - 1)

        $branch     = if ($last) { "\-- " } else { "+-- " }
        $nextPrefix = if ($last) { $prefix + "    " } else { $prefix + "|   " }

        # -------------------------
        # FOLDER
        # -------------------------
        if ($item.PSObject.Properties.Name -contains "item") {
            $lineNumStr = "<Line Nr. {0:D3}> " -f $global:lineCounter
            $lineText = "$prefix$branch$($item.name)"
            
            # console output
            Write-Host "$lineNumStr$lineText" -ForegroundColor White

            # log output
            if (-not $NoLog) { "$lineNumStr$lineText" | Out-File -Append -FilePath $global:LogFile }

            $global:lineCounter++

            # recurse
            Print-Tree -items $item.item -prefix $nextPrefix -NoLog:$NoLog
            continue
        }

        # -------------------------
        # REQUEST
        # -------------------------
        if ($item.PSObject.Properties.Name -contains "request") {
            $method = $item.request.method.ToUpper()

            # method colors
            switch ($method) {
                "GET"    { $methodColor = "Green" }
                "POST"   { $methodColor = "DarkYellow" }
                "PUT"    { $methodColor = "Cyan" }
                "DELETE" { $methodColor = "Red" }
                default  { $methodColor = "White" }
            }

            $lineNumStr = "<Line Nr. {0:D3}> " -f $global:lineCounter
            $lineText = "$prefix$branch[$method] $($item.name)"

            # console output: color only for method
            $prefixPart = "$lineNumStr$prefix$branch["
            $postMethodPart = "] $($item.name)"
            Write-Host -NoNewline $prefixPart
            Write-Host -NoNewline $method -ForegroundColor $methodColor
            Write-Host $postMethodPart

            # log output (plain text)
            if (-not $NoLog) { "$lineNumStr$lineText" | Out-File -Append -FilePath $global:LogFile }

            $global:lineCounter++
        }
    }
}



function Format-UriFixedWidth {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [int]$MaxLength = 34
    )

    if (-not $Uri) { return "" }

    if ($Uri.Length -le $MaxLength) {
        return $Uri
    }

    # Always show first 30, "..", last 3
    return $Uri.Substring(0, 30) + ".." + $Uri.Substring($Uri.Length - 3)
}


function Get-MaxLengths {
    param(
        [array]$items,
        [string]$prefix = ""
    )

    foreach ($i in $items) {
        $isLast = ($i -eq $items[-1])
        $branch = if ($isLast) { "\-- " } else { "+-- " }
        $nextPrefix = if ($isLast) { $prefix + "    " } else { $prefix + "|   " }

        if ($i.PSObject.Properties.Name -contains "request") {

            # --- TREE / NAME ---
            $leftText = "$prefix$branch$($i.name)"
            $global:maxLeftLength = [Math]::Max($global:maxLeftLength, $leftText.Length)

            # --- METHOD ---
            $method = $i.request.method.ToUpper()
            $global:maxMethodLength = [Math]::Max($global:maxMethodLength, $method.Length)

            # --- TRY TO GET STATUS / TIME / TCP / URL ---
            $url = $null
            if ($i.request.url -is [string]) { $url = $i.request.url }
            elseif ($i.request.url -and $i.request.url.raw) { $url = $i.request.url.raw }
            elseif ($i.request.url -and $i.request.url.href) { $url = $i.request.url.href }
            else { $url = "<unknown>" }

            try {
                $result = Invoke-Request-With-Metrics -Url $url -Method $method
                $statusCode = $result.Status
                $timeMs     = $result.TimeMs
                $tcp        = $result.Tcp
                $responseUrl = if ($result.Response -and $result.Response.BaseResponse) { $result.Response.BaseResponse.ResponseUri.AbsoluteUri } else { $url }
            } catch {
                $statusCode = "ERR"
                $timeMs     = "n/a"
                $tcp        = "FAIL"
                $responseUrl = $url
            }

            # --- CALCULATE MAX LENGTHS ---
            $global:maxStatusLength = [Math]::Max($global:maxStatusLength, ($statusCode.ToString()).Length)
            $global:maxTimeLength   = [Math]::Max($global:maxTimeLength, ("${timeMs}ms").Length)
            $global:maxTcpLength    = [Math]::Max($global:maxTcpLength, $tcp.Length)
            $global:maxUrlLength    = [Math]::Max($global:maxUrlLength, $responseUrl.Length)
        }

        if ($i.PSObject.Properties.Name -contains "item") {
            Get-MaxLengths -items $i.item -prefix $nextPrefix
        }
    }
}


# ==========================================================
# FULL Print-Tree-With-Execution WITH METHOD & STATUS ALIGNMENT
# ==========================================================
function Print-Tree-With-Execution {
    param(
        [array]$items,
        [object]$collection,
        [string]$prefix = "",
        [bool]$isLast = $true,
        [switch]$NoLog
    )

    # Initialize globals if not set
    if (-not $global:maxLeftLength)   { $global:maxLeftLength = 0 }
    if (-not $global:maxMethodLength) { $global:maxMethodLength = 0 }
    if (-not $global:maxStatusLength) { $global:maxStatusLength = 0 }
    if (-not $global:maxTimeLength)   { $global:maxTimeLength = 0 }
    if (-not $global:maxTcpLength)    { $global:maxTcpLength = 0 }
    if (-not $global:lineCounter)     { $global:lineCounter = 1 }

    # First pass → calculate alignment
    Get-MaxLengths -items $items -prefix $prefix

    # Print tree
    for ($i = 0; $i -lt $items.Count; $i++) {
        $item = $items[$i]
        $last = ($i -eq $items.Count - 1)
        $branch = if ($last) { "\-- " } else { "+-- " }
        $nextPrefix = if ($last) { $prefix + "    " } else { $prefix + "|   " }

        # -------------------------
        # FOLDER
        # -------------------------
        if ($item.PSObject.Properties.Name -contains "item") {
            $leftText = "$prefix$branch$($item.name)"
            $lineNumStr = "<Line Nr. {0:D3}> " -f $global:lineCounter

            # console output
            Write-Host "$lineNumStr$leftText" -ForegroundColor White

            # log output
            if (-not $NoLog) { "$lineNumStr$leftText" | Out-File -Append -FilePath $global:LogFile }

            $global:lineCounter++

            # recurse
            Print-Tree-With-Execution -items $item.item -collection $collection -prefix $nextPrefix -isLast $last -NoLog:$NoLog
            continue
        }

        # -------------------------
        # REQUEST
        # -------------------------
        if ($item.PSObject.Properties.Name -contains "request") {
            $method = $item.request.method.ToUpper()
            $authHeader = Resolve-Auth -request $item -collection $collection
            $headers = @{} + $authHeader
            $body = ""

            if ($method -in @("POST","PUT","PATCH") -and $item.request.body) {
                if ($item.request.body.mode -eq "raw") {
                    $body = $item.request.body.raw
                }
            }

            # URL
            if ($item.request.url -is [string]) { $url = $item.request.url }
            elseif ($item.request.url -and $item.request.url.raw) { $url = $item.request.url.raw }
            elseif ($item.request.url -and $item.request.url.href) { $url = $item.request.url.href }
            else { $url = "<unknown>" }

            # Execute request
            $result = Invoke-Request-With-Metrics -Url $url -Method $method -Headers $headers -Body $body
            $statusCode = $result.Status
            $timeMs     = $result.TimeMs
            $tcp        = $result.Tcp

            if ($result.Response -and $result.Response.BaseResponse) {
                $responseUrl = $result.Response.BaseResponse.ResponseUri.AbsoluteUri
            } else {
                $responseUrl = $url
            }

            # Colors for console
            switch ($method) {
                "GET"  { $methodColor = "Green" }
                "POST" { $methodColor = "DarkYellow" }
                default { $methodColor = "White" }
            }
            $statusColor = if ($statusCode -ge 200 -and $statusCode -lt 300) { "Green" } else { "Red" }
            $tcpColor    = if ($tcp -match "OK") { "Green" } else { "Red" }

            # Short URL
            try {
                $uri = [System.Uri]$responseUrl
                $segments = $uri.AbsolutePath.Trim("/").Split("/")
                if ($segments.Count -ge 2) {
                    $shortPath = "/" + ($segments[-2..-1] -join "/")
                } else {
                    $shortPath = $uri.AbsolutePath
                }
                $shortUrl = "$($uri.Scheme)://$($uri.Host)$shortPath"
            } catch {
                $shortUrl = $responseUrl
            }

            $displayUrl = Format-UriFixedWidth -Uri $shortUrl -MaxLength 34

            # Alignment padding
            $leftText = "$prefix$branch$($item.name)"
            $padding1 = " " * ($global:maxLeftLength - $leftText.Length + 1)
            $methodPadded = $method + " " * ($global:maxMethodLength - $method.Length)
            $statusPadded = $statusCode.ToString() + " " * ($global:maxStatusLength - $statusCode.ToString().Length)
            $timePadded   = "${timeMs}ms" + " " * ($global:maxTimeLength - ("${timeMs}ms").Length)
            $tcpPadded    = $tcp + " " * ($global:maxTcpLength - $tcp.Length)

            # Console output
            $lineNumStr = "<Line Nr. {0:D3}> " -f $global:lineCounter
            Write-Host -NoNewline $lineNumStr
            Write-Host -NoNewline "$leftText$padding1[" 
            Write-Host -NoNewline $methodPadded -ForegroundColor $methodColor
            Write-Host -NoNewline "] ["
            Write-Host -NoNewline $statusPadded -ForegroundColor $statusColor
            Write-Host -NoNewline "] $timePadded | "
            Write-Host -NoNewline $tcpPadded -ForegroundColor $tcpColor
            Write-Host " | $displayUrl"

            # Log output (matches console exactly, plain text)
            if (-not $NoLog) {
                "$lineNumStr$leftText [$method] [$statusCode] ${timeMs}ms | $tcp | $displayUrl" |
                    Out-File -Append -FilePath $global:LogFile
            }

            # Always log full request + response details
			Log-Request-Details -RequestName $item.name -Method $method -Url $url -Headers $headers -Body $body -Result $result

            $global:lineCounter++
        }
    }
}





function Read-InteractiveSelection {
    param (
        [string]$Prompt,
        [string[]]$Values
    )

    if (-not $Values -or $Values.Count -eq 0) { return }

    $inputBuffer = ""
    $startPos = $Host.UI.RawUI.CursorPosition
    $matchIndex = 0

    Write-Host $Prompt -NoNewline

    while ($true) {
        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

        switch ($key.VirtualKeyCode) {

            13 { # ENTER
				if ($Values -contains $inputBuffer) {
					Write-Host ""   # ← force line break after user input
					return $inputBuffer
				}
			}

            9 { # TAB → autocomplete / cycle

                # 🔑 CORE FIX:
                # If input is a full match → cycle through ALL values
                if ($Values -contains $inputBuffer) {
                    $matches = $Values
                } else {
                    $matches = @($Values | Where-Object { $_.StartsWith($inputBuffer) })
                }

                if ($matches.Count -eq 0) { break }

                if ($matches -contains $inputBuffer) {
                    $matchIndex = ($matchIndex + 1) % $matches.Count
                } else {
                    $matchIndex = 0
                }

                $inputBuffer = $matches[$matchIndex]
            }

            8 { # BACKSPACE
                if ($inputBuffer.Length -gt 0) {
                    $inputBuffer = $inputBuffer.Substring(0, $inputBuffer.Length - 1)
                    $matchIndex = 0
                }
            }

            default {
                if ($key.Character -and $key.Character -ne "`0") {
                    $inputBuffer += $key.Character
                    $matchIndex = 0
                }
            }
        }

        # Vorschau (UNCHANGED, incl. [+tab])
        $preview = @($Values | Where-Object { $_.StartsWith($inputBuffer) })
        $suggestion = ""
        if ($preview.Count -gt 0 -and $preview[0] -ne $inputBuffer) {
            $suggestion = $preview[0].Substring($inputBuffer.Length) + " [+tab]"
        }

        # redraw
        $Host.UI.RawUI.CursorPosition = $startPos
        Write-Host -NoNewline (" " * ($Host.UI.RawUI.WindowSize.Width - 1))
        $Host.UI.RawUI.CursorPosition = $startPos

        # print prompt (normal color)
		Write-Host -NoNewline $Prompt

		# print user input (yellow)
		Write-Host -NoNewline $inputBuffer -ForegroundColor Yellow

		# print suggestion (gray)
		if ($suggestion) {
			Write-Host -NoNewline $suggestion -ForegroundColor DarkGray
		}
    }
}



# ==========================================================
# ⭐ TAB-Autocomplete (inline, first match only + cycling)
# ==========================================================
function Show-InteractiveTree {
    param ([array]$items)

    function Flatten-Tree($items) {
        $out = @()
        foreach ($i in $items) {
            if ($i.PSObject.Properties.Name -contains "request") {
                $out += [PSCustomObject]@{
                    Name   = $i.name.Trim()
                    Object = $i
                }
            }
            if ($i.PSObject.Properties.Name -contains "item") {
                $out += Flatten-Tree -items $i.item
            }
        }
        return $out
    }

    $flat = @(Flatten-Tree -items $items)
    if ($flat.Count -eq 0) { return }

    # ⬅ allow N as escape
    $names = $flat.Name + 'N'

    $selectedName = Read-InteractiveSelection `
        -Prompt "Please input an API (or N to go back): " `
        -Values $names

    if (-not $selectedName) { return }

    if ($selectedName -eq 'N') {
        return 'N'
    }

    return ($flat | Where-Object Name -eq $selectedName)[0].Object
}

# ==========================================================
# TAB-Autocomplete for File Selection
# ==========================================================
function Show-InteractiveFileSelection {
    param ([array]$files)

    $fileNames = @($files | ForEach-Object { $_.Name })

    return Read-InteractiveSelection `
        -Prompt "Please input the name of your file: " `
        -Values $fileNames
}

# ==========================================================
# ⭐ Unified HTTP Request Executor with Metrics (ALL METHODS)
# ==========================================================
function Invoke-Request-With-Metrics {
    param (
        [string]$Url,
        [string]$Method,
        [hashtable]$Headers = @{},
        [string]$Body = $null,
        [int]$TimeoutSec = 30
    )

    # ------------------------------------------------------
    # TCP Connectivity Check (always executed)
    # ------------------------------------------------------
    $tcpStatus = Test-TCPConnection-Compact -url $Url

    $statusCode = "ERR"
    $elapsedMs  = "n/a"
    $response   = $null

    try {
        $params = @{
            Uri             = $Url
            Method          = $Method
            Headers         = $Headers
            TimeoutSec      = $TimeoutSec
            ErrorAction     = 'Stop'
            UseBasicParsing = $true
        }

        # Body is optional (GET safely ignores it)
        if ($Body -and $Body.Trim() -ne "") {
            $params.Body = $Body
        }

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $response = Invoke-WebRequest @params
        $sw.Stop()

        $statusCode = $response.StatusCode
        $elapsedMs  = $sw.ElapsedMilliseconds
    }
    catch {
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }

        if ($sw) {
            $sw.Stop()
            $elapsedMs = $sw.ElapsedMilliseconds
        }
    }

    return @{
        Status   = $statusCode
        TimeMs   = $elapsedMs
        Tcp      = $tcpStatus
        Response = $response
    }
}


# ==========================================================
# ⭐ Progress Bar Funktion
# ==========================================================
function Show-ProgressBar {
    param (
        [int]$current,
        [int]$total,
        [int]$barLength = 10
    )

    $percent = ($current / $total)
    $filledLength = [Math]::Floor($percent * $barLength)
    $emptyLength = $barLength - $filledLength
    $bar = "[{0}{1}] {2}%" -f ('#' * $filledLength), ('-' * $emptyLength), [int]($percent*100)
    
    Write-Host -NoNewline "`r$bar"
    if ($current -eq $total) { Write-Host "" }  # neue Zeile am Ende
}


function Show-MainMenu {
    Write-Section "Main Menu"
    Write-Host "|| [1] Check Single API || [2] Check Whole Project || [3] Stress Test ||"
    Write-Host "Selection (1/2/3): " -NoNewline
    return $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character
}

function Show-Request-Block {
    param (
        [string]$method,
        [string]$url,
        [hashtable]$headers,
        [string]$body = ""
    )

    Write-BlockBoundary "REQUEST START"
    # headers & body logging only inside REQUEST
    Write-Section "Parsed Request"
    Log-Message "full-url: $url"
    Log-Message "method: $method"
    $uri = [System.Uri]$url
    Log-Message "protocol: $($uri.Scheme)"
    Log-Message "domain: $($uri.Host)"
    Log-Message "resource: $($uri.AbsolutePath)"
    if ($uri.Query) {
        Log-Message "parameters:"
        $query = $uri.Query.TrimStart('?').Split('&')
        foreach ($pair in $query) {
            $kv = $pair.Split('=',2)
            $key = [System.Web.HttpUtility]::UrlDecode($kv[0])
            $val = if ($kv.Count -gt 1) { [System.Web.HttpUtility]::UrlDecode($kv[1]) } else { "" }
            Log-Message "---${key}: ${val}"
        }
    } else {
        Log-Message "parameters: none"
    }

    Write-Section "Request Headers"
    if ($headers.Count -eq 0) {
        Log-Message "(no headers)"
    } else {
        foreach ($key in ($headers.Keys | Sort-Object)) {
            $val = $headers[$key]
            if ($key -match 'authorization|cookie') { $val = "******" }
            Log-Message "${key}: ${val}"
        }
    }

    Write-Section "Request Body"
    if ($body -and $body.Trim() -ne "") {
        try {
            $pretty = ($body | ConvertFrom-Json | ConvertTo-Json -Depth 10)
            foreach ($line in $pretty -split "`n") { Log-Message $line }
        } catch {
            foreach ($line in $body -split "`n") { Log-Message $line }
        }
    } else {
        Log-Message "not supplied"
    }

    Write-BlockBoundary "REQUEST END"
}


function Show-Response-Summary {
    param ([hashtable]$Result)
    Write-BlockBoundary "RESPONSE START"
    Write-Section "Response Summary"
    Log-Message "HTTP Status: $($Result.Status)"
    Log-Message "Duration: $($Result.TimeMs) ms"
    Log-Message "TCP: $($Result.Tcp)"
}


function Show-Response-Details {
    param (
        [hashtable]$Result
    )

    $response = $Result.Response
    if (-not $response) {
        Write-BlockBoundary "RESPONSE END"
        return
    }

    Write-Section "Response Headers"
    foreach ($key in ($response.Headers.Keys | Sort-Object)) {
        Write-Host ("{0}: {1}" -f $key, $response.Headers[$key])
    }

    Write-Section "Response Cookies"
    $cookies = Parse-ResponseCookies -Response $response
    if ($cookies.Count -eq 0) {
        Write-Host "No cookies returned"
    } else {
        foreach ($c in $cookies) {
            Write-Host "$($c.Name) = $($c.Value)"
        }
    }

    Write-Section "Response Body"
    if ($response.Content -and $response.Content.Trim() -ne "") {
        try {
            $pretty = ($response.Content | ConvertFrom-Json | ConvertTo-Json -Depth 10)
            $pretty -split "`n" | ForEach-Object { Write-Host $_ }
        } catch {
            $response.Content -split "`n" | ForEach-Object { Write-Host $_ }
        }
    } else {
        Write-Host "(empty body)"
    }

    Write-BlockBoundary "RESPONSE END"
}


function Log-Request-Details {
    param (
        [Parameter(Mandatory)]
        [string]$RequestName,
        [string]$Method,
        [string]$Url,
        [hashtable]$Headers = @{},
        [string]$Body = "",
        [hashtable]$Result
    )

    # -------------------------
    # REQUEST DETAILS
    # -------------------------
    Log-Only "===== REQUEST START: $RequestName ====="
    Log-Only "Full URL: $Url"
    Log-Only "Method: $Method"

    try {
        $uri = [System.Uri]$Url
        Log-Only "Protocol: $($uri.Scheme)"
        Log-Only "Domain: $($uri.Host)"
        Log-Only "Resource: $($uri.AbsolutePath)"

        if ($uri.Query) {
            Log-Only "Parameters:"
            foreach ($pair in $uri.Query.TrimStart('?').Split('&')) {
                $kv = $pair.Split('=',2)
                $key = [System.Web.HttpUtility]::UrlDecode($kv[0])
                $val = if ($kv.Count -gt 1) { [System.Web.HttpUtility]::UrlDecode($kv[1]) } else { "" }
                Log-Only "---${key}: $val"
            }
        } else {
            Log-Only "Parameters: none"
        }
    } catch {
        Log-Only "Invalid URL format"
    }

    Log-Only "Headers:"
    if ($Headers.Count -eq 0) {
        Log-Only "(no headers)"
    } else {
        foreach ($k in ($Headers.Keys | Sort-Object)) {
            $v = $Headers[$k]
            if ($k -match 'authorization|cookie') { $v = "******" }
            Log-Only "${k}: $v"
        }
    }

    Log-Only "Body:"
    if ($Body -and $Body.Trim() -ne "") {
        try {
            $pretty = ($Body | ConvertFrom-Json | ConvertTo-Json -Depth 10)
            foreach ($line in $pretty -split "`n") { Log-Only $line }
        } catch {
            foreach ($line in $Body -split "`n") { Log-Only $line }
        }
    } else {
        Log-Only "(not supplied)"
    }
    Log-Only "===== REQUEST END =====`n"

    # -------------------------
    # RESPONSE DETAILS
    # -------------------------
    Log-Response-Details -Result $Result
}


function Log-Response-Details {
    param (
        [Parameter(Mandatory)]
        [hashtable]$Result
    )

    $response = $Result.Response
    if (-not $response) {
        Log-Only "No HTTP response received"
        return
    }

    Log-Only "HTTP Status: $($Result.Status)"
    Log-Only "----------------------------------------"

    Log-Only "Response Headers"
    foreach ($key in ($response.Headers.Keys | Sort-Object)) {
        Log-Only ("{0}: {1}" -f $key, $response.Headers[$key])
    }

    Log-Only "Response Cookies"
    $cookies = Parse-ResponseCookies -Response $response
    if ($cookies.Count -eq 0) {
        Log-Only "No cookies returned"
    } else {
        foreach ($c in $cookies) {
            Log-Only "$($c.Name) = $($c.Value)"
        }
    }

    Log-Only "Response Body"
    if ($response.Content -and $response.Content.Trim() -ne "") {
        try {
            $pretty = ($response.Content | ConvertFrom-Json | ConvertTo-Json -Depth 10)
            foreach ($line in $pretty -split "`n") { Log-Only $line }
        } catch {
            foreach ($line in $response.Content -split "`n") { Log-Only $line }
        }
    } else {
        Log-Only "(empty body)"
    }
}


# ==========================
# RUN-MAINMENU FUNCTION
# ==========================
function Run-MainMenu {
    param (
        [Parameter(Mandatory)]
        $collectionJson
    )

    Write-Section "Main Menu" -NoLog
    Write-Host "|| [1] Check single API || [2] Check whole project || [3] Stress test ||"
    Write-Host "Selection (1/2/3): " -NoNewline

    $menuKey = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character
    Write-Host ""

    switch ($menuKey) {

        '1' {
            Clear-Screen
            do {
                # console tree only
                Print-Tree -items $collectionJson.item -NoLog

                $selectedRequestObj = Show-InteractiveTree -items $collectionJson.item
                if ($selectedRequestObj -eq 'N') { return }

                Clear-Screen
                Print-Tree -items $collectionJson.item -NoLog

                $method = $selectedRequestObj.request.method.ToUpper()
                $url = if ($selectedRequestObj.request.url -is [string]) { $selectedRequestObj.request.url }
                       elseif ($selectedRequestObj.request.url.raw) { $selectedRequestObj.request.url.raw }
                       elseif ($selectedRequestObj.request.url.href) { $selectedRequestObj.request.url.href }
				
				# 🔖 Request name (visible + logged)
				$requestName = $selectedRequestObj.name
				Write-Request-Header -RequestName $requestName

                $headers = Resolve-Auth -request $selectedRequestObj -collection $collectionJson
                $body = if ($method -in @("POST","PUT","PATCH") -and $selectedRequestObj.request.body -and $selectedRequestObj.request.body.mode -eq "raw") {
                    $selectedRequestObj.request.body.raw
                } else { "" }

                # =====================
                # EXECUTION MODE ON
                # =====================
                $Global:LoggingExecutionOnly = $true

                Show-Request-Block -method $method -url $url -headers $headers -body $body
                Test-TCPConnection -url $url

                $result = Invoke-Request-With-Metrics -Url $url -Method $method -Headers $headers -Body $body
                Show-Response-Summary -Result $result

                do {
					Write-Host "Show response details? (J/N): " -NoNewline
					$key = ([string]$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
					Write-Host ""
				} while ($key -notin @('J','N'))

				# 📝 ALWAYS log response details exactly once
				Log-Response-Details -Result $result

				# 👀 Show in console ONLY if user pressed J
				if ($key -eq 'J') {
					Show-Response-Details -Result $result
				}
                # =====================
                # EXECUTION MODE OFF
                # =====================
                $Global:LoggingExecutionOnly = $false

            } while ($true)
        }

        '2' {
            Clear-Screen
            $Global:LoggingExecutionOnly = $true
			Print-Tree-With-Execution -items $collectionJson.item -collection $collectionJson -NoLog:$false
			$Global:LoggingExecutionOnly = $false
        }

        '3' {
            Clear-Screen
            do {
                Print-Tree -items $collectionJson.item -NoLog
                $selectedRequestObj = Show-InteractiveTree -items $collectionJson.item
                if ($selectedRequestObj -eq 'N') { return }

                $method = $selectedRequestObj.request.method.ToUpper()
                $url = $selectedRequestObj.request.url.raw
                $headers = Resolve-Auth -request $selectedRequestObj -collection $collectionJson
                $body = if ($method -in @("POST","PUT","PATCH") -and $selectedRequestObj.request.body -and $selectedRequestObj.request.body.mode -eq "raw") {
                    $selectedRequestObj.request.body.raw
                } else { "" }

                $iterations = 100
                $totalTime = 0

                Write-Section "Running Stress Test ($iterations requests)" -NoLog

                $Global:LoggingExecutionOnly = $true
                for ($i=1; $i -le $iterations; $i++) {
                    $result = Invoke-Request-With-Metrics -Url $url -Method $method -Headers $headers -Body $body
                    if ($result.TimeMs -ne "n/a") { $totalTime += $result.TimeMs }
                    Show-ProgressBar -current $i -total $iterations
                }
                $Global:LoggingExecutionOnly = $false

                Write-Section "Stress Test Results" -NoLog
                $avgTime = [math]::Round($totalTime / $iterations, 2)
                Log-Message "Average response time: $avgTime ms" -Color Green -NoLog

            } while ($true)
        }

        default { Write-Host "Invalid selection." -ForegroundColor Red }
    }
}


# ------------------------------------------------------
# 🔐 STEP 0 — Initialize log file FIRST (CRITICAL)
# ------------------------------------------------------

$global:lineCounter = 1

# Windows username → lastname
$winUser = (Get-WmiObject -Class Win32_ComputerSystem).username
if ($winUser -match "\\(.+)$") {
	$lastName = $matches[1].ToLower()
} else {
	$lastName = $winUser.ToLower()
}

# Timestamp (seconds included to avoid collisions)
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Create ONE log file for this run (collection name added later only in content)
$global:LogFile = Join-Path `
	$global:logFolder `
	"${lastName}_${timestamp}_api_test_log.txt"
		

# ==========================================================
# 🔁 MAIN EXECUTION LOOP (Y/N RESTART) — FIXED
# ==========================================================

$runAgain = $true

while ($runAgain) {

    Clear-Host
    # ------------------------------------------------------
    # STEP 1 — Select Postman collection (NOW SAFE TO LOG)
    # ------------------------------------------------------
	Log-Message
	
    $selectedFile = Select-PostmanCollection
    if (-not $selectedFile) { break }

    $collectionJson = Get-Content $selectedFile -Raw | ConvertFrom-Json

    # ------------------------------------------------------
    # STEP 2 — Print initial collection tree
    # ------------------------------------------------------

    Write-Section "Collection Tree"
    Log-Message "Root"
    Print-Tree -items $collectionJson.item

    # ------------------------------------------------------
    # STEP 3 — Main menu
    # ------------------------------------------------------

    Run-MainMenu -collectionJson $collectionJson

    # ------------------------------------------------------
    # STEP 4 — Restart?
    # ------------------------------------------------------

    Write-Host "Do you want to select another Postman collection? (Y/N): " -NoNewline

    while ($true) {
        $key = ([string]$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        Write-Host ""

        if ($key -eq 'Y') {
            Clear-Host
            $runAgain = $true
            break
        }
        elseif ($key -eq 'N') {
            $runAgain = $false
            break
        }
    }
}

Write-Section "Script finished"
Log-Message "Execution terminated by user"
