function Convert-StringToB64 {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline)]
		[ValidateNotNullOrEmpty()]
		[string]
		$String,
        [Parameter(Mandatory = $false, Position = 1)]
		[switch]
		$Compress = $false,
        [Parameter(Mandatory = $false, Position = 2)]
		[ValidateNotNullOrEmpty()]
		[string]
		$Encoding = "Unicode"
	)

    switch ($Encoding) {
        "ASCII" { $Bytes = [Text.Encoding]::ASCII.GetBytes($String) }
        "Unicode" { $Bytes = [Text.Encoding]::Unicode.GetBytes($String) }
        "UTF8" { $Bytes = [Text.Encoding]::UTF8.GetBytes($String) }
        Default { Write-Error "Non supported Encoding specified. Choose from ASCII, Unicode and UTF8" }
    }

    if ($Compress)
    {
        $MemoryStream = New-Object IO.MemoryStream
        $DeflateStream = New-Object IO.Compression.DeflateStream ($MemoryStream, [IO.Compression.CompressionMode]::Compress)
        $DeflateStream.Write($Bytes, 0, $Bytes.Length)
        $DeflateStream.Close()
        $Bytes = $MemoryStream.ToArray()
    }

    $B64 = [Convert]::ToBase64String($Bytes)

    Write-Output $B64

}

function Convert-StringFromB64 {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline)]
		[ValidateNotNullOrEmpty()]
		[string]
		$B64String,
        [Parameter(Mandatory = $false, Position = 1)]
		[switch]
		$Compress = $false,
        [Parameter(Mandatory = $false, Position = 2)]
		[ValidateNotNullOrEmpty()]
		[string]
		$Encoding = "Unicode"
	)

    $Bytes = [Convert]::FromBase64String($B64String)

    if ($Compress)
    {
        $MemoryStream = New-Object IO.MemoryStream (, $Bytes)
        $DeflateStream = New-Object IO.Compression.DeflateStream ($MemoryStream, [IO.Compression.CompressionMode]"Decompress")
        $StreamReader = New-Object IO.StreamReader ($DeflateStream, [Text.Encoding]::ASCII)
        $TmpString = $StreamReader.ReadToEnd()
        $Bytes = [Text.Encoding]::ASCII.GetBytes($TmpString)
    }

    switch ($Encoding) {
        "ASCII" { $String = [Text.Encoding]::ASCII.GetString($Bytes) }
        "Unicode" { $String = [Text.Encoding]::Unicode.GetString($Bytes) }
        "UTF8" { $String = [Text.Encoding]::UTF8.GetString($Bytes) }
        Default { Write-Error "Non supported Encoding specified. Choose from ASCII, Unicode and UTF8" }
    }

    Write-Output $String

}


function Package-CompressedB64 {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline)]
		[ValidateNotNullOrEmpty()]
		[string]
		$B64String,
        [Parameter(Mandatory = $false, Position = 1)]
		[switch]
		$ReEncode = $false,
        [Parameter(Mandatory = $false, Position = 2)]
		[switch]
		$AmsiBypass = $false,
        [Parameter(Mandatory = $false, Position = 3)]
		[ValidateNotNullOrEmpty()]
		[string]
		$Encoding = "Unicode"
	)

    $Decompressor = 'IEX((New-Object IO.StreamReader((New-Object IO.Compression.DeflateStream((New-Object IO.MemoryStream(,[Convert]::FromBase64String("'+ $B64String +'"))),[IO.Compression.CompressionMode]"Decompress")),[Text.Encoding]::'+ $Encoding +')).ReadToEnd())'

    $BGonAmsi = '' # TODO

    if ($AmsiBypass) 
    {
        $Decompressor = $BGonAmsi + $Decompressor
    }

    if ($ReEncode)
    {
        $Decompressor = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Decompressor))
    }

    Write-Output $Decompressor

}

$inject = "SQBFAFgAKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABJAE8ALgBTAHQAcgBlAGEAbQBSAGUAYQBkAGUAcgAoACgATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgAuAEQAZQBmAGwAYQB0AGUAUwB0AHIAZQBhAG0AKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABJAE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQAoACwAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiADcAVgBqAGIAVAB0AHQAQQBFAEoAMwBYAFYAdQBvAC8AVwBHAG0AawBPAEMASgBZAHYAYQBtAHEASwB2AFUAQgBRAG8AcQBRAEMAawBSAHQAZQBwAEUAUQBEADIAbAB3AGcARABiAEYAVQBlAEoAQQBVAGMAVwAvADkAOAB5AHMASABkAHYAcgA5AGMAWgB4AEsAQgBTAEUATABOAHYAWgAzAGIAbQBjAEcAYwAvAE0AegBtAFoASQBNAHoAcQBqAEEAWQBWADAAUwBnAEYAKwBPAGQAUwBXADkAegBuADUATgBNAEgAcwBPAG4AMwBDAGMANABMAFYATQB6AHEAbQBIAHQAWQAyADYAVABXADkAQQB0ADAAZgBlAGsASwBQADYAUgBFAGQAZwBPAE0AWABIAGQARQBJAEgAQwBGAFcAbQBmAEkAbwBvAG4AZQBwAFMAWQBjAFIAWABaAGYANgBrAE4ATQBIAHIAUgB2AE4ATQBHADgAeQB5ADkAeQBzADAANgBWAGQAagBGAGwARwBIAHoATQBCAFoAaQA2AGgANwBSADMAdQB1AGkAQwBaAGcAYQBxAEYAVQBSAGQAcgBVACsAaABKAGsARABQAE4ATQAxAG4ANwBBAHQANgBSAFUATAA0AEgAUgB3AEQAcABYAFYAQwBOAE0AUgA0AEoATQBqACsARgBpADEARQBvACsAdABOAEkAcAAwADkANwA0AEEAbgB4AG4ARwBGADIAUgBQAHUAUQAwAFkARwBNAE0AZQBZAHUATQB6AFkAeAA3AHoAVABsAG4AMgBTACsAbgB2AEYAYgBTACsAWQBkADcAVgByAFcAKwBxAEcAZwBuAEYAcgB0AGYANQA1AEQAZAB5AEUAMABBAHoAcgBKAG8ARwB1AEwAVgA4AGEAUQA3ADQATgBtAGEAdABSAHgAVQA1AGgAZgAzAE0ARABYADYARQBpAFUAQgAvAFAASQBWAEoAcAByADkAQgBtAGoAMAAyAGoARgB4ADEAaAB4AE4ATwBXAGQAdABqAC8AdABSAHcAZABhADgAeABLAGIAOAA1AHoAUQBmAFYAYQBqAEQAVQBSAEQAbQAzAFoAdwAxAFkAUwBLAFAAYgBNAEoAOQBLAEYANABYADIARQA1AFEASABiADUAOQBCAHQAegBYAGsANwAyAEkAYgAzAEYAbABVAGoAeABhAEQAdgBLAHQAbABpAEcAcQAwAFUAYwBvADcAawBxAFEASwBQAGIAWABCADEAUgBWAHQASwBxAHEASAByAEkAMQBqAGMAcgA0AGwARQB5AFYAawBHAHkAQgBYAHEATwBXAG8ANgAyAE0ATQBMAHkAVgBmAGgAWQAwAGoAbwAwAFQANgBTAG0AVABBAFQAMQBYAGgAVABIAFUAOQBDAFAAYwBRAFYAUwBOAFgAMwBnAGMAZwB3AHgATgA1AFUAYQBOAE0AQgA0AGkASgB1AHAAUABLAG0ANABKADYAQQBLAEoARQBzAGMAcgBLAGkASwA1AGEAUwArAE4AKwBkAE8AMQB0AGQATwBsAEgARgBPAHgAbQA5AFoAaQA2ADUAeQBVAGMAeAA2AFYAZgBUAHEAKwBkAC8ATQAwAEoAbgBqAHUASQA0ADgAOQA4AEcAbABNAGwAeAA1ADAANQBkAEsAbwBMADcAUABIAGsAWQBYADgATgBBACsAZgBhAGMAZgBZAGkAZgA3AGIAdwBkAGoAcgA1AEQAVAByAEUAZAA5AGcAMQBHAFUALwA4AHQAcAAwAGkAMQBUAGwAYwBhAHoAeQBuAFEAdAB0AHIAVQBrADgAdQB5AHkAegBmAE8ANwAwAGIAZABTAHMAVwBuADMAZQBCAG4AYgB2AFYAUQBjAHUAcABuADgAWQBJAHgAcQA1ADAAdgBQAGUAdgBRAEIAYgA0ADYAOABFAEIARgBXAFIAVgA4AGIAOAB5AG8AdQAzAFUASgArAFAAVQB1AEwAUABlAGwASgAvADcAQQBoACsAZABPAFAAYQByAGMAOQBYAHUAdgB6AGIAawBQAGwAZgA3AFkAMwBVAFgANQBWAFAAVQBsAGYAVQBEAEoAdABPAHMAdQB6AFgAcwBwAFgAOQBYAFIAZQA3AHkATwBEAFEAMwB5AGYAbQBjAFIAUwByAEQAbgBtAFMATABBAE4AbAArAHEAWQA0AHYANwBqAG8AVwBzAHEAdAAwADkAdgA1AHIANwBoAFEAKwA5ADAAMQAzAHMAbgAwADAANQB1AHkAdQBRAGsAVgAyAHoAWgByAE0ALwBtADkAZgAxAC8AdQB4AHkAagAwAGEAdgB6ADgAdgBYADQAYgB1ADUAOQBOAGQARQArADAASwBoAHEAaABmAGEAbgA5AFgAKwBVADkANQBGAEUAeQBXAEwAcgBpAHoAbABkAHEAMQArAFYAbABlAFcANwA3AHkATABrAFAAYgBFAHcASABaAHQAeABKAGgAYwBoADgAKwBZAGoAMwBzAFUANgBVAGcAZgBLADcANwBTAHIAbgB4AGoAeQBpAEIAZgB0AHkATgBkAC8ARABzAHIANwBxADQAcABkAHQAbAAxAC8AKwBaAE4AUQBGAFUAegBtAHMAMQBCAFYAWABQAHAAWgBxAEIAcQBpADcARwBtAG8AQwBwAGIANwBmAEIAcQB5AGQAWAA5AHAAWAArAFYANwBRAEgATQBmAHkATAB2ADcAZwBIADcAaQBlAFMAdwB5ADkAYwByAEkARgBqADcAMABnAGYAZQBuAEQAKwBUAGEAbgBVAFMAMQBiADkAUgB4AFcAMwAxAGcARQBlAFkATgA2AEcAUgB1AHoAdgAyAHgAOQBGAG0AMwAyADcAKwArAHYAQgBQADkAcQA2AG0ARABDAGUAWQA5AFMAUQBNADEAcQBVAFAAZgBnAE0AZQB0ADEASgA4AHMANABsAHUAKwBxADEAcwBrAHMAYQBqAGYANAB5ADYAMQBhAG0AOQBlAGcAeAAvAFcAeQBEAEgAbQByAG8ATwBWAGgAdgBSADgAZgBMAFgAKwBZAFUAKwBwAHAAQwAvAGEARwBXAE8AawArAGMAaABnAG4AQwB5AGwAcQBEAE4AcgBZAHQAMQAwAHYAdABrAFcAaABIAEYAMgB4AFgASABSAHcAUABNAHAANwBoADYAcwAzAGMASgBkAGYARgBJAHgANQBTAFgAdgB5AG0AWABPAEsALwBiAG8ATgBLAEYAYgBzAC8ASwBWAC8AUQA5AFIAcgAzAC8AbABUAGwAZAAyAHQARgBYACsANAA3AG0AZQAvADYAbQBMAGMARABVAFgAOQBzAFMAMgBQAHMATABtADQANgBTAG4AKwBBAHMAPQAiACkAKQApACwAWwBJAE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ATQBvAGQAZQBdACIARABlAGMAbwBtAHAAcgBlAHMAcwAiACkAKQAsAFsAVABlAHgAdAAuAEUAbgBjAG8AZABpAG4AZwBdADoAOgBVAG4AaQBjAG8AZABlACkAKQAuAFIAZQBhAGQAVABvAEUAbgBkACgAKQApAA=="
#[Text.encoding]::Unicode.GetString([convert]::FromBase64String($inject)) | IEX; ("Convert-StringToB64", "Convert-StringFromB64", "Package-CompressedB64") | Format-Table
