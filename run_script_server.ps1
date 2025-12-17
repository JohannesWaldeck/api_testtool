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

function Invoke-GETRequest {
    param ([string]$url, [hashtable]$headers)

    try {
        Write-Section "GET REQUEST"
        Log-Message "Fetching CSRF token and cookies..."

        $response = Invoke-WebRequest -Uri $url -Method Get -Headers $headers -UseBasicParsing -ErrorAction Stop

        Log-Message "GET Response Headers:"
        $response.Headers.GetEnumerator() | ForEach-Object { 
            Log-Message "    $($_.Key): $($_.Value)" 
        }

        Log-Message "GET HTTP Response Code: $($response.StatusCode)" -Color Green
        Log-Message "GET Status Description: $($response.StatusDescription)"

        return $response
    } catch {
        Log-Message "Error during GET request: $_" -Color Red
        exit 1
    }
}

function Invoke-POSTRequest {
    param ([string]$url, [hashtable]$headers, [string]$body)

    try {
        Write-Section "POST REQUEST"
        Show-Request -method "POST" -url $url -headers $headers -body $body

        $postResponse = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body -ErrorAction Stop
        $postResponseJson = $postResponse | ConvertTo-Json -Depth 10

        Log-Message "POST request response:"
        foreach ($line in $postResponseJson -split "`n") {
            Log-Message $line
        }
    } catch {
        Log-Message "Error during POST request: $_" -Color Red
    }
}

function Print-Tree {
    param([array]$items, [string]$prefix = "")
    foreach ($item in $items) {
        if ($item.PSObject.Properties.Name -contains "request") {
            $url = $item.request.url
            Log-Message "${prefix}- $($item.name) -> $url"
        } elseif ($item.PSObject.Properties.Name -contains "item") {
            Log-Message "${prefix}- $($item.name)"
            Print-Tree -items $item.item -prefix ($prefix + "|   ")
        }
    }
}

function Print-Tree-With-Execution {
    param([array]$items, [string]$prefix = "")
    foreach ($item in $items) {
        # FOLDER
        if ($item.PSObject.Properties.Name -contains "item") {
            Log-Message "${prefix}- $($item.name)"
            Print-Tree-With-Execution -items $item.item -prefix ($prefix + "|   ")
        }
        # REQUEST
        elseif ($item.PSObject.Properties.Name -contains "request") {
            # URL sauber ermitteln
            if ($item.request.url -is [string]) {
                $url = $item.request.url
            } elseif ($item.request.url.raw) {
                $url = $item.request.url.raw
            } elseif ($item.request.url.href) {
                $url = $item.request.url.href
            } else {
                $url = "<unknown>"
            }
			
			$method = $item.request.method.ToUpper()
            # Request ausführen und Metriken
            $result = Invoke-Request-With-Metrics -url $url -method $method
			
			switch ($method) {
				"GET"  { $methodColor = "Green" }
				"POST" { $methodColor = "DarkYellow" }
				default { $methodColor = "White" }
			}

            # Statusfarbe bestimmen
            $statusCode = $result.Status
            $timeMs = $result.TimeMs
			$tcp    = $result.Tcp
            if ($statusCode -eq 200) { $statusColor = "Green" } else { $statusColor = "Red" }

            # Zeile bauen
            $linePrefix = "${prefix}- $($item.name) "
			$methodTag  = "[$method] "
			$lineAfter  = "-> $url ["
            $lineSuffix = "] ${timeMs}ms | $tcp"

            # Console-Ausgabe mit farbigem Statuscode
            $lineNumStr = "<Line Nr. {0:D3}> " -f $global:lineCounter
            Write-Host -NoNewline $lineNumStr
			Write-Host -NoNewline $linePrefix
			Write-Host -NoNewline $methodTag -ForegroundColor $methodColor
			Write-Host -NoNewline $lineAfter
			Write-Host -NoNewline $statusCode -ForegroundColor $statusColor
			Write-Host $lineSuffix

            # Logfile
            $linePrefix + $statusCode + $lineSuffix | Out-File -Append -FilePath "log.txt"

            $global:lineCounter++
        }
    }
}

# ==========================================================
# ⭐ TAB-Autocomplete (inline, first match only)
# ==========================================================
function Show-InteractiveTree {
    param ([array]$items)

    function Flatten-Tree($items) {
        $out = @()
        foreach ($i in $items) {
            if ($i.PSObject.Properties.Name -contains "request") {
                $out += [PSCustomObject]@{ Object = $i; Name = $i.name.Trim() }
            }
            if ($i.PSObject.Properties.Name -contains "item") {
                $out += Flatten-Tree -items $i.item
            }
        }
        return $out
    }

    $flatItems = @(Flatten-Tree -items $items)
    if ($flatItems.Count -eq 0) { return }

    $inputBuffer = ""
    $startPos = $Host.UI.RawUI.CursorPosition

    Write-Host "Please input an API: " -NoNewline

    while ($true) {
        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

        switch ($key.VirtualKeyCode) {
            13 { # ENTER
                $match = $flatItems | Where-Object { $_.Name -eq $inputBuffer }
                if (-not $match) {
                    $match = $flatItems | Where-Object { $_.Name.StartsWith($inputBuffer) }
                }
                if ($match) { return $match[0].Object }
            }
            9 { # TAB
                $match = $flatItems | Where-Object { $_.Name.StartsWith($inputBuffer) }
                if ($match) { $inputBuffer = $match[0].Name }
            }
            8 { # BACKSPACE
                if ($inputBuffer.Length -gt 0) { $inputBuffer = $inputBuffer.Substring(0, $inputBuffer.Length - 1) }
            }
            default {
                if ($key.Character -and $key.Character -ne "`0") { $inputBuffer += $key.Character }
            }
        }

        # Compute suggestion
        $match = $flatItems | Where-Object { $_.Name.StartsWith($inputBuffer) }
        $suggestion = ""
        if ($match) {
            $firstMatch = $match[0].Name
            if ($inputBuffer -ne $firstMatch) {
                $suggestion = $firstMatch.Substring($inputBuffer.Length) + " [+tab]"
            }
        }

        # Move cursor back to start position
        $Host.UI.RawUI.CursorPosition = $startPos

        # Clear the line exactly
        $width = $Host.UI.RawUI.WindowSize.Width
        Write-Host -NoNewline (" " * ($width - 1))

        # Rewrite line with input + suggestion in quotes
		$Host.UI.RawUI.CursorPosition = $startPos
		Write-Host -NoNewline "Please input an API: $inputBuffer"
		if ($suggestion) { Write-Host -NoNewline $suggestion -ForegroundColor DarkGray }
    }
}

# ==========================================================
# TAB-Autocomplete for File Selection
# ==========================================================
function Show-InteractiveFileSelection {
    param ([array]$files)

    $fileNames = @($files | ForEach-Object { $_.Name })
    $inputBuffer = ""
    $startPos = $Host.UI.RawUI.CursorPosition

    Write-Host "Please input the name of your file: " -NoNewline

    while ($true) {
        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

        switch ($key.VirtualKeyCode) {
            13 { # ENTER
                $matches = @($fileNames | Where-Object { $_.StartsWith($inputBuffer) })
                if ($matches.Count -gt 0) {
                    Write-Host ""
                    return $matches[0]
                }
            }
            8 { # BACKSPACE
                if ($inputBuffer.Length -gt 0) {
                    $inputBuffer = $inputBuffer.Substring(0, $inputBuffer.Length - 1)
                }
            }
            9 { # TAB
                $matches = @($fileNames | Where-Object { $_.StartsWith($inputBuffer) })
                if ($matches.Count -gt 0) {
                    $inputBuffer = $matches[0]
                }
            }
            default {
                if ($key.Character -match '[\x20-\x7E]') {
                    $inputBuffer += $key.Character
                }
            }
        }

        # Compute suggestion
        $matches = @($fileNames | Where-Object { $_.StartsWith($inputBuffer) })
        $suggestion = ""
        if ($matches.Count -gt 0) {
            $firstMatch = $matches[0]
            if ($inputBuffer -ne $firstMatch) {
                $suggestion = $firstMatch.Substring($inputBuffer.Length) + " [+tab]"
            }
        }

        # Move cursor back to start position
        $Host.UI.RawUI.CursorPosition = $startPos

        # Clear the line exactly
        $width = $Host.UI.RawUI.WindowSize.Width
        Write-Host -NoNewline (" " * ($width - 1))

        # Rewrite line with input + suggestion
        $Host.UI.RawUI.CursorPosition = $startPos
        Write-Host -NoNewline "Please input the name of your file: $inputBuffer"
        if ($suggestion) { Write-Host -NoNewline $suggestion -ForegroundColor DarkGray }
    }
}

function Invoke-Request-With-Metrics {
    param (
        [string]$url,
        [string]$method
    )

    $statusCode = "ERR"
    $elapsedMs = "n/a"

    # ⭐ TCP Check (immer)
    $tcpStatus = Test-TCPConnection-Compact -url $url

    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $response = Invoke-WebRequest `
			-Uri $url `
			-Method $method `
			-UseBasicParsing `
			-TimeoutSec 30 `
			-ErrorAction Stop
        $sw.Stop()

        $statusCode = $response.StatusCode
        $elapsedMs = $sw.ElapsedMilliseconds
    } catch {
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        if ($sw) {
            $sw.Stop()
            $elapsedMs = $sw.ElapsedMilliseconds
        }
    }

    return @{
        Status = $statusCode
        TimeMs = $elapsedMs
        Tcp    = $tcpStatus
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


# =============================== #
# MENÜ
# =============================== #

Write-Section "Hauptmenue"
Log-Message "Displaying menu options"
Write-Host "|| [1] Check single API || [2] Check whole project || [3] Stress test ||"

# Prompt user without logging interfering
Write-Host "Auswahl (1/2/3): " -NoNewline
$menuKey = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character
Write-Host ""  # just move to new line

# Log menu selection separately
Log-Message "Menue Selection: $menuKey"

#######################################################################
# MODUS 1 — SINGLE API
#######################################################################
if ($menuKey -eq '1') {
    Log-Message "Modus: Single API"

    Write-Section "Postman Collection Selection"
    $postmanFiles = Get-ChildItem -Path "C:\Users\johan\OneDrive\Dokumente" -Filter "*.json"

    if ($postmanFiles.Count -eq 0) {
        Log-Message "No .json files found." -Color Red
        exit
    }

    Log-Message "Please select a Postman Collection: "
    for ($i=0; $i -lt $postmanFiles.Count; $i++) {
        Log-Message "$($postmanFiles[$i].Name)"
    }

    $selection = Show-InteractiveFileSelection -files $postmanFiles
    $selectedFile = $postmanFiles | Where-Object { $_.Name -eq $selection }
    if (-not $selectedFile) {
        Log-Message "Invalid Fileselection." -Color Red
        exit
    }
    $selectedFile = $selectedFile.FullName
    Log-Message "Selected File: $selectedFile"

    Write-Section "Load Postman Collection"
    $collectionJson = Get-Content $selectedFile -Raw | ConvertFrom-Json

    # Baum anzeigen
    Log-Message "Root"
    Print-Tree -items $collectionJson.item

    # Benutzer auswählen lassen
    $selectedRequestObj = Show-InteractiveTree -items $collectionJson.item
    Write-Host ""
    Log-Message "Selected API: $($selectedRequestObj.name)"

    # Methode & URL ermitteln
    $method = $selectedRequestObj.request.method.ToUpper()
    if ($selectedRequestObj.request.url -is [string]) {
        $url = $selectedRequestObj.request.url
    } elseif ($selectedRequestObj.request.url.raw) {
        $url = $selectedRequestObj.request.url.raw
    } elseif ($selectedRequestObj.request.url.href) {
        $url = $selectedRequestObj.request.url.href
    }

    # Auth Header auflösen
    $authHeader = Resolve-Auth -request $selectedRequestObj -collection $collectionJson

    # Basis-Header
    $headers = @{} + $authHeader

    # Body aus Postman (falls vorhanden)
    $body = ""
    if ($method -eq "POST" -and $selectedRequestObj.request.body) {
        if ($selectedRequestObj.request.body.mode -eq "raw") {
            $body = $selectedRequestObj.request.body.raw
        }
    }

	# Bestätigung
	Write-Section "API Call verification"
	$prompt3 = "Do you want to run the selected API call? (J/N): "
	Write-Host $prompt3 -NoNewline
	$confirm = Read-Host
	Log-Message "$prompt3 $confirm"

	if ($confirm -ne "J") {
		Log-Message "API Call canceled."
		Write-Section "Skript ended"
		exit
	}

	# 🔍 Parsed Request anzeigen VOR der echten Request-Ausführung
	Show-Request `
		-method $method `
		-url $url `
		-headers $headers `
		-body $body

	# TCP Connection immer testen
	Test-TCPConnection -url $url

	# ============================
	# EXECUTION
	# ============================
	if ($method -eq "GET") {
		# CSRF Preflight
		$headers['x-csrf-token'] = 'Fetch'
		$response = Invoke-GETRequest -url $url -headers $headers

		$csrfToken = $response.Headers['x-csrf-token']
		$responseCookies = $response.Headers['Set-Cookie']
		$filteredCookies = @()

		if ($responseCookies) {
			foreach ($cookie in $responseCookies) {
				$cookieParts = $cookie -split ','
				foreach ($part in $cookieParts) {
					$clean = $part.Trim()
					foreach ($allowedCookie in $allowedCookies) {
						if ($clean -like "${allowedCookie}=*") {
							$escaped = [regex]::Escape($allowedCookie)
							if ($clean -match ($escaped + '([^;]+)')) {
								$filteredCookies += $matches[0]
							}
						}
					}
				}
			}
		}

		$cookies = $filteredCookies -join '; '

		$postHeaders = @{
			'x-csrf-token'  = $csrfToken
			'Accept'        = 'application/json'
			'Content-Type'  = 'application/json'
			'Cookie'        = $cookies
		} + $authHeader

		Invoke-POSTRequest -url $url -headers $postHeaders -body $body

	} elseif ($method -eq "POST") {
		# POST-only Request
		Invoke-POSTRequest -url $url -headers $headers -body $body
	}
    elseif ($method -eq "POST") {

        # POST-only Request
        Invoke-POSTRequest -url $url -headers $headers -body $body

    }
    else {
        Log-Message "HTTP method '$method' not supported." -Color Yellow
    }

    Write-Section "Skript ended"
    exit
}

#######################################################################
# MODUS 2 — WHOLE PROJECT
#######################################################################
elseif ($menuKey -eq '2') {
    Log-Message "Modus: Whole Project"

    if (-not $collectionJson) {
        Write-Section "Postman Collection Selection"
        $postmanFiles = Get-ChildItem -Path . -Filter "*.json"

        if ($postmanFiles.Count -eq 0) {
            Log-Message
			            Log-Message "No .json files found." -Color Red
            exit
        }

        Log-Message "Please select a postman collection: "
        for ($i=0; $i -lt $postmanFiles.Count; $i++) {
            Log-Message "$($postmanFiles[$i].Name)"
        }

        $selection = Show-InteractiveFileSelection -files $postmanFiles
        $selectedFile = $postmanFiles | Where-Object { $_.Name -eq $selection }
        if (-not $selectedFile) {
            Log-Message "Invalid Fileselection." -Color Red
            exit
        }
        $selectedFile = $selectedFile.FullName
        Log-Message "Selected File: $selectedFile"

        $collectionJson = Get-Content $selectedFile -Raw | ConvertFrom-Json
    }

    $rootFolders = $collectionJson.item
    Log-Message "Root"
    Print-Tree-With-Execution -items $rootFolders

    Write-Section "Skript beendet"
    exit
}

#######################################################################
# MODUS 3 — STRESS TEST
#######################################################################
elseif ($menuKey -eq '3') {
    Log-Message "Modus: Stress Test"

    # Postman Collection Auswahl
    Write-Section "Postman Collection Selection"
    $postmanFiles = Get-ChildItem -Path "C:\Users\johan\OneDrive\Dokumente" -Filter "*.json"

    if ($postmanFiles.Count -eq 0) {
        Log-Message "No .json files found." -Color Red
        exit
    }

    Log-Message "Please select a Postman Collection: "
    for ($i=0; $i -lt $postmanFiles.Count; $i++) {
        Log-Message "$($postmanFiles[$i].Name)"
    }

    $selection = Show-InteractiveFileSelection -files $postmanFiles
    $selectedFile = $postmanFiles | Where-Object { $_.Name -eq $selection }
    if (-not $selectedFile) {
        Log-Message "Invalid Fileselection." -Color Red
        exit
    }
    $selectedFile = $selectedFile.FullName
    Log-Message "Selected File: $selectedFile"

    $collectionJson = Get-Content $selectedFile -Raw | ConvertFrom-Json

    # Baum anzeigen
    Log-Message "Root"
    Print-Tree -items $collectionJson.item

    # Request auswählen
    $selectedRequestObj = Show-InteractiveTree -items $collectionJson.item
    Write-Host ""
    Log-Message "Selected API for stress test: $($selectedRequestObj.name)"

    # Bestätigung
    Write-Section "Stress Test Verification"
    $prompt3 = "Do you want to run the stress test for the selected API call 100 times? (J/N): "
    Write-Host $prompt3 -NoNewline
    $confirm = Read-Host
    Log-Message "$prompt3 $confirm"

    if ($confirm -ne "J") {
        Log-Message "Stress Test canceled."
        Write-Section "Skript ended"
        exit
    }

    # Methode & URL ermitteln
    $method = $selectedRequestObj.request.method.ToUpper()
    if ($selectedRequestObj.request.url -is [string]) {
        $url = $selectedRequestObj.request.url
    } elseif ($selectedRequestObj.request.url.raw) {
        $url = $selectedRequestObj.request.url.raw
    } elseif ($selectedRequestObj.request.url.href) {
        $url = $selectedRequestObj.request.url.href
    }

    # Auth Header auflösen
    $authHeader = Resolve-Auth -request $selectedRequestObj -collection $collectionJson

    # Basis-Header
    $headers = @{} + $authHeader

    # Body aus Postman (falls vorhanden)
    $body = ""
    if ($method -eq "POST" -and $selectedRequestObj.request.body) {
        if ($selectedRequestObj.request.body.mode -eq "raw") {
            $body = $selectedRequestObj.request.body.raw
        }
    }

    # Stress Test: 100 Requests
    $iterations = 100
    $totalTime = 0

    Write-Section "Running Stress Test ($iterations requests)"
    for ($i = 1; $i -le $iterations; $i++) {
        $result = Invoke-Request-With-Metrics -url $url -method $method
        $timeMs = $result.TimeMs
        if ($timeMs -ne "n/a") { $totalTime += $timeMs }

        Show-ProgressBar -current $i -total $iterations
    }

    $averageTime = if ($totalTime -ne 0) { [math]::Round($totalTime / $iterations, 2) } else { "n/a" }
    Write-Section "Stress Test Results"
    Log-Message "Completed $iterations requests for '$($selectedRequestObj.name)'"
    Log-Message "Average response time: $averageTime ms" -Color Green

    Write-Section "Skript ended"
    exit
}

else {
    Log-Message "Invalid Menue selection." -Color Red
    exit
}