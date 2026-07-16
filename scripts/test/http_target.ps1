param(
    [Parameter(Mandatory)] [int]$Port,
    [Parameter(Mandatory)] [string]$Body,
    [string]$ListenAddress = "127.0.0.1"
)

$ErrorActionPreference = "Stop"
$listener = [System.Net.Sockets.TcpListener]::new(
    [System.Net.IPAddress]::Parse($ListenAddress),
    $Port
)
$listener.Start()
try {
    while ($true) {
        $client = $listener.AcceptTcpClient()
        try {
            $stream = $client.GetStream()
            $stream.ReadTimeout = 5000
            $buffer = [byte[]]::new(4096)
            $request = [System.IO.MemoryStream]::new()
            while ($request.Length -lt 16384) {
                $read = $stream.Read($buffer, 0, $buffer.Length)
                if ($read -eq 0) { break }
                $request.Write($buffer, 0, $read)
                if ([System.Text.Encoding]::ASCII.GetString($request.ToArray()).Contains("`r`n`r`n")) {
                    break
                }
            }
            if ($request.Length -eq 0) { continue }

            $payload = [System.Text.Encoding]::UTF8.GetBytes($Body)
            $headers = [System.Text.Encoding]::ASCII.GetBytes(
                "HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`nContent-Length: $($payload.Length)`r`nConnection: close`r`n`r`n"
            )
            $stream.Write($headers, 0, $headers.Length)
            $stream.Write($payload, 0, $payload.Length)
            $stream.Flush()
        } catch {
            # Readiness probes connect and close without sending a request.
        } finally {
            $client.Dispose()
        }
    }
} finally {
    $listener.Stop()
}
