# =============================== #
# PowerShell Script: GET/POST
# =============================== #

$baseUrl = "http://localhost:3000/test"
$global:lineCounter = 1
$allowedCookies = @('sap-XSRF_WC1_100', 'sap-usercontext')
$postData = @{ '' = '' } | ConvertTo-Json

# =============================== #
# Funktionen
# =============================== #

function Resolve-Auth {
    param (
        [object]$request,
        [object]$collection
    )

    $authObj = $null

    # Request-specific Auth
    if ($request.request.auth -and $request.request.auth.type -ne "inherit") {
        $authObj = $request.request.auth
    } else {
        # Collection Auth
        $authObj = $collection.auth
    }

    if (-not $authObj) { return @{} }

    switch ($authObj.type) {
        "basic" {
            $username = $authObj.basic.username
            $password = $authObj.basic.password
            $base64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${username}:${password}"))
            return @{ 'Authorization' = "Basic $base64Auth" }
        }
        "oauth2" {
            $token = $authObj.oauth2.accessToken
            return @{ 'Authorization' = "Bearer $token" }
        }
        default {
            return @{}
        }
    }
}

function Log-Message {
    param (
        [string]$message,
        [ValidateSet("Default","Red","Green","Yellow","Cyan","Magenta","Blue","White")]
        [string]$Color = "Default"
    )

    $lineNum = $global:lineCounter.ToString("D3")
    $numberedMessage = "<Line Nr. $lineNum> $message"

    if ($Color -eq "Default") {
        Write-Host $numberedMessage
    } else {
        Write-Host $numberedMessage -ForegroundColor $Color
    }

    $numberedMessage | Out-File -Append -FilePath "log.txt"
    $global:lineCounter++
}

function Write-Section {
    param([string]$title)
    Write-Host ""
    Log-Message "----- $title -----" -Color Cyan
}


function Select-PostmanCollection {
    param (
        [string]$folderPath = $PSScriptRoot  # Automatically points to the script folder
    )

    $postmanFiles = Get-ChildItem -Path $folderPath -Filter "*.json"
    if ($postmanFiles.Count -eq 0) {
        Log-Message "No .json files found in $folderPath." -Color Red
        exit
    }

    Log-Message "Please select a Postman Collection: "
    for ($i=0; $i -lt $postmanFiles.Count; $i++) {
        Log-Message "$($postmanFiles[$i].Name)"
    }

    $selection = Show-InteractiveFileSelection -files $postmanFiles
    $selectedFile = $postmanFiles | Where-Object { $_.Name -eq $selection }
    if (-not $selectedFile) {
        Log-Message "Invalid file selection." -Color Red
        exit
    }

    Write-Host ""   # ✅ FIX: restore newline after interactive input

    Log-Message "Selected File: $($selectedFile.Name)"
    return $selectedFile.FullName
}


function Test-TCPConnection-Compact {
    param ([string]$url)

    try {
        $uri = [System.Uri]$url
        $client = New-Object System.Net.Sockets.TcpClient
        $client.Connect($uri.Host, $uri.Port)
        $client.Close()
        return "TCP OK"
    } catch {
        return "TCP FAIL"
    }
}


function Test-TCPConnection {
    param ([string]$url)

    try {
        $uri = New-Object System.Uri($url)
        $hostname = $uri.Host
        $port = $uri.Port

        Write-Section "Testing TCP Connection"
        Log-Message "Testing TCP Connection to: $hostname on port $port"

        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($hostname, $port)

        if ($tcpClient.Connected) {
            Log-Message "Connection to $hostname on port $port succeeded." -Color Green
            $tcpClient.Close()
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

    Log-Message "method: $($method.ToLower())"
    Log-Message "protocol: $($uri.Scheme)"
    Log-Message "domain: $($uri.Host)"
    Log-Message "resource: $($uri.AbsolutePath)"

    if ($uri.Query) {
        Log-Message "parameters:"
        $query = $uri.Query.TrimStart('?').Split('&')
        foreach ($pair in $query) {
            $kv = $pair.Split('=',2)
            $key = [System.Web.HttpUtility]::UrlDecode($kv[0])
            $val = if ($kv.Count -gt 1) {
                [System.Web.HttpUtility]::UrlDecode($kv[1])
            } else {
                ""
            }
            Log-Message "---${key}: ${val}"
        }
    } else {
        Log-Message "parameters: none"
    }
}


function Show-Request {
    param (
        [string]$method,
        [string]$url,
        [hashtable]$headers,
        [string]$body = "",
        [switch]$previewOnly
    )

    if (-not $previewOnly) {
        Write-Section "Parsed Request"
        $uri = [System.Uri]$url

        Log-Message "method: $($method.ToLower())"
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
    }

    Write-Section "Request Headers"
    if ($headers.Count -eq 0) {
        Log-Message "(no headers)"
    } else {
        foreach ($key in ($headers.Keys | Sort-Object)) {
            $val = $headers[$key]
            if ($key -match 'authorization|cookie') { $val = "******" }
            Log-Message "${key}: $val"
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
}


function Print-Tree {
    param (
        [array]$items,
        [string]$prefix = "",
        [bool]$isLast = $true
    )

    for ($i = 0; $i -lt $items.Count; $i++) {
        $item = $items[$i]
        $last = ($i -eq $items.Count - 1)

        # Tree symbols
        $branch = if ($last) { "\-- " } else { "+-- " }
        $nextPrefix = if ($last) { "    " } else { "|   " }

        # FOLDER
        if ($item.PSObject.Properties.Name -contains "item") {
            Log-Message "$prefix$branch$($item.name)"
            Print-Tree `
                -items $item.item `
                -prefix ($prefix + $nextPrefix) `
                -isLast $last
        }

        # REQUEST
        elseif ($item.PSObject.Properties.Name -contains "request") {
            $method = $item.request.method.ToUpper()
            Log-Message "$prefix$branch[$method] $($item.name)"
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
        [bool]$isLast = $true
    )

    # -------------------------------
    # Initialize globals if not set
    # -------------------------------
    if (-not $global:maxLeftLength)   { $global:maxLeftLength = 0 }
    if (-not $global:maxMethodLength) { $global:maxMethodLength = 0 }
    if (-not $global:maxStatusLength) { $global:maxStatusLength = 0 }
    if (-not $global:maxTimeLength)   { $global:maxTimeLength = 0 }
    if (-not $global:maxTcpLength)    { $global:maxTcpLength = 0 }
    if (-not $global:lineCounter)     { $global:lineCounter = 1 }

    # -------------------------------
    # First pass → calculate alignment
    # -------------------------------
    Get-MaxLengths -items $items -prefix $prefix

    # -------------------------------
    # Print tree
    # -------------------------------
    for ($i = 0; $i -lt $items.Count; $i++) {

        $item = $items[$i]
        $last = ($i -eq $items.Count - 1)

        $branch     = if ($last) { "\-- " } else { "+-- " }
        $nextPrefix = if ($last) { $prefix + "    " } else { $prefix + "|   " }

        # -------------------------
        # FOLDER
        # -------------------------
        if ($item.PSObject.Properties.Name -contains "item") {
            Log-Message "$prefix$branch$($item.name)"
            Print-Tree-With-Execution `
                -items $item.item `
                -collection $collection `
                -prefix $nextPrefix `
                -isLast $last
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

            # --- URL ---
            if ($item.request.url -is [string]) {
                $url = $item.request.url
            }
            elseif ($item.request.url -and $item.request.url.raw) {
                $url = $item.request.url.raw
            }
            elseif ($item.request.url -and $item.request.url.href) {
                $url = $item.request.url.href
            }
            else {
                $url = "<unknown>"
            }

            # --- EXECUTE ---
            $result = Invoke-Request-With-Metrics `
                -Url $url `
                -Method $method `
                -Headers $headers `
                -Body $body

            $statusCode = $result.Status
            $timeMs     = $result.TimeMs
            $tcp        = $result.Tcp

            if ($result.Response -and $result.Response.BaseResponse) {
                $responseUrl = $result.Response.BaseResponse.ResponseUri.AbsoluteUri
            } else {
                $responseUrl = $url
            }

            # --- COLORS ---
            switch ($method) {
                "GET"  { $methodColor = "Green" }
                "POST" { $methodColor = "DarkYellow" }
                default { $methodColor = "White" }
            }

            if ($statusCode -ge 200 -and $statusCode -lt 300) {
                $statusColor = "Green"
            } else {
                $statusColor = "Red"
            }

            if ($tcp -match "OK") {
                $tcpColor = "Green"
            } else {
                $tcpColor = "Red"
            }

            # --- SHORT URL ---
            try {
                $uri = [System.Uri]$responseUrl
                $segments = $uri.AbsolutePath.Trim("/").Split("/")

                if ($segments.Count -ge 2) {
                    $shortPath = "/" + ($segments[-2..-1] -join "/")
                } else {
                    $shortPath = $uri.AbsolutePath
                }

                $shortUrl = "$($uri.Scheme)://$($uri.Host)$shortPath"
            }
            catch {
                $shortUrl = $responseUrl
            }

            # --- FINAL URL FORMAT (NO POWERSHELL ELLIPSIS) ---
            $displayUrl = Format-UriFixedWidth -Uri $shortUrl -MaxLength 34

            # --- ALIGNMENT ---
            $leftText = "$prefix$branch$($item.name)"
            $padding1 = " " * ($global:maxLeftLength - $leftText.Length + 1)

            $methodPadded = $method + " " * ($global:maxMethodLength - $method.Length)
            $statusText   = $statusCode.ToString()
            $statusPadded = $statusText + " " * ($global:maxStatusLength - $statusText.Length)
            $timeText     = "${timeMs}ms"
            $timePadded   = $timeText + " " * ($global:maxTimeLength - $timeText.Length)
            $tcpPadded    = $tcp + " " * ($global:maxTcpLength - $tcp.Length)

            # --- OUTPUT ---
            $lineNumStr = "<Line Nr. {0:D3}> " -f $global:lineCounter
            Write-Host -NoNewline $lineNumStr
            Write-Host -NoNewline "$leftText$padding1["
            Write-Host -NoNewline $methodPadded -ForegroundColor $methodColor
            Write-Host -NoNewline "] ["
            Write-Host -NoNewline $statusPadded -ForegroundColor $statusColor
            Write-Host -NoNewline "] $timePadded | "
            Write-Host -NoNewline $tcpPadded -ForegroundColor $tcpColor
            Write-Host " | $displayUrl"

            # --- LOG ---
            "$leftText [$methodPadded] [$statusPadded] $timePadded | TCP $tcpPadded | $displayUrl" |
                Out-File -Append -FilePath "log.txt"

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

        Write-Host -NoNewline "$Prompt$inputBuffer"
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


function Run-MainMenu {
    param (
        [Parameter(Mandatory)]
        $collectionJson
    )

    # =============================== #
    # MENÜ
    # =============================== #

    Write-Section "Hauptmenue"
    Log-Message "Displaying menu options"
    Write-Host "|| [1] Check single API || [2] Check whole project || [3] Stress test ||"

    # Prompt user without logging interfering
    Write-Host "Auswahl (1/2/3): " -NoNewline
    $menuKey = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character
    Write-Host ""

    # Log menu selection separately
    Log-Message "Menue Selection: $menuKey"

    #######################################################################
	# MODUS 1 — SINGLE API (repeat request selection)
	#######################################################################
	if ($menuKey -eq '1') {

		Log-Message "Modus: Single API"

		do {
			Write-Section "Load Postman Collection"
			Log-Message "Root"
			Print-Tree -items $collectionJson.item

			# Select request OR N
			$selectedRequestObj = Show-InteractiveTree -items $collectionJson.item
			Write-Host ""

			if ($selectedRequestObj -eq 'N') {
				Log-Message "Returning to main menu"
				break
			}

			Write-Host ""
			Log-Message "Selected API: $($selectedRequestObj.name)"

			# Method & URL
			$method = $selectedRequestObj.request.method.ToUpper()
			if ($selectedRequestObj.request.url -is [string]) {
				$url = $selectedRequestObj.request.url
			} elseif ($selectedRequestObj.request.url.raw) {
				$url = $selectedRequestObj.request.url.raw
			} elseif ($selectedRequestObj.request.url.href) {
				$url = $selectedRequestObj.request.url.href
			}

			# Auth + Headers
			$authHeader = Resolve-Auth -request $selectedRequestObj -collection $collectionJson
			$headers = @{} + $authHeader

			# Body
			$body = ""
			if ($method -eq "POST" -and $selectedRequestObj.request.body) {
				if ($selectedRequestObj.request.body.mode -eq "raw") {
					$body = $selectedRequestObj.request.body.raw
				}
			}

			# Preview
			Show-Request `
				-method $method `
				-url $url `
				-headers $headers `
				-body $body

			Test-TCPConnection -url $url

			# Execute
			$result = Invoke-Request-With-Metrics `
				-Url $url `
				-Method $method `
				-Headers $headers `
				-Body $body

			if ($result.Status -eq 200) {
				Log-Message "HTTP $($result.Status) completed in $($result.TimeMs) ms" -Color Green
			} else {
				Log-Message "HTTP $($result.Status) failed in $($result.TimeMs) ms" -Color Red
			}

			Write-Section "Execution finished (Single API)"
			Log-Message "Select another API or press N to go back"

		}
		while ($true)

		return
	}

    #######################################################################
    # MODUS 2 — WHOLE PROJECT
    #######################################################################
    elseif ($menuKey -eq '2') {
        Log-Message "Modus: Whole Project"

        Log-Message "Root"
        Print-Tree-With-Execution `
		-items $collectionJson.item `
		-collection $collectionJson

        Write-Section "Skript beendet"
        return
    }

    #######################################################################
	# MODUS 3 — STRESS TEST (repeat request selection)
	#######################################################################
	elseif ($menuKey -eq '3') {

		Log-Message "Modus: Stress Test"

		do {
			Log-Message "Root"
			Print-Tree -items $collectionJson.item

			# Select request OR N
			$selectedRequestObj = Show-InteractiveTree -items $collectionJson.item
			Write-Host ""

			if ($selectedRequestObj -eq 'N') {
				Log-Message "Returning to main menu"
				break
			}

			Write-Host ""
			Log-Message "Selected API for stress test: $($selectedRequestObj.name)"

			# Method & URL
			$method = $selectedRequestObj.request.method.ToUpper()
			if ($selectedRequestObj.request.url -is [string]) {
				$url = $selectedRequestObj.request.url
			} elseif ($selectedRequestObj.request.url.raw) {
				$url = $selectedRequestObj.request.url.raw
			} elseif ($selectedRequestObj.request.url.href) {
				$url = $selectedRequestObj.request.url.href
			}

			# Auth + Headers
			$authHeader = Resolve-Auth -request $selectedRequestObj -collection $collectionJson
			$headers = @{} + $authHeader

			# Body
			$body = ""
			if ($method -eq "POST" -and $selectedRequestObj.request.body) {
				if ($selectedRequestObj.request.body.mode -eq "raw") {
					$body = $selectedRequestObj.request.body.raw
				}
			}

			# Stress test
			$iterations = 100
			$totalTime = 0

			Write-Section "Running Stress Test ($iterations requests)"
			for ($i = 1; $i -le $iterations; $i++) {
				$result = Invoke-Request-With-Metrics -Url $url -Method $method -Headers $headers -Body $body
				if ($result.TimeMs -ne "n/a") { $totalTime += $result.TimeMs }
				Show-ProgressBar -current $i -total $iterations
			}

			$averageTime = if ($totalTime -ne 0) {
				[math]::Round($totalTime / $iterations, 2)
			} else { "n/a" }

			Write-Section "Stress Test Results"
			Log-Message "Completed $iterations requests for '$($selectedRequestObj.name)'"
			Log-Message "Average response time: $averageTime ms" -Color Green

			Write-Section "Execution finished (Stress Test)"
			Log-Message "Select another API or press N to go back"

		}
		while ($true)

		return
	}

    else {
        Log-Message "Invalid Menue selection." -Color Red
        return
    }
}


# ==========================================================
# 🔁 MAIN EXECUTION LOOP (Y/N RESTART)
# ==========================================================

$runAgain = $true

do {

    # Reset line counter per run (optional but clean)
    $global:lineCounter = 1

    # -------------------------------
    # Select Postman Collection
    # -------------------------------
    Write-Section "Postman Collection Selection"
    $selectedFile = Select-PostmanCollection

    if (-not $selectedFile) {
        Log-Message "No file selected. Exiting." -Color Red
        break
    }

    $collectionJson = Get-Content $selectedFile -Raw | ConvertFrom-Json

    # -------------------------------
    # Run Main Menu
    # -------------------------------
    Run-MainMenu -collectionJson $collectionJson

    # -------------------------------
    # Ask user if they want to restart
    # -------------------------------
    Write-Host ""
    Write-Host "Do you want to select another Postman collection? (Y/N): " -NoNewline

    while ($true) {
        $key = ([string]$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        Write-Host ""

        if ($key -eq 'Y') {
            Log-Message "User chose to load another Postman collection"
            $runAgain = $true
            break
        }
        elseif ($key -eq 'N') {
            Log-Message "User chose to end execution"
            $runAgain = $false
            break
        }
        else {
            Write-Host "Please press Y or N: " -NoNewline
        }
    }

}
while ($runAgain)

Write-Section "Script finished"
Log-Message "Execution terminated by user"