<#
.SYNOPSIS
    OpenStack Swift operations from PowerShell
.DESCRIPTION
    .
.PARAMETER command
	list [dir] [-recurse] 					List files (add / to directories)
	info [file]								Get File infos
	upload source destination				Upload a file
	upload_archive source destination		Upload and extract archive (only supports .tar.gz and .tar.bz2 files)
	upload_folder source destination		Upload folder recursively (needs full path for source)
	download source destination				Download a file (filename in destination)
	delete file								Delete a file

.PARAMETER recurse
List recursively
.PARAMETER debuger
Show request
.PARAMETER uploadlog
Write uploaded files names to logfile
.PARAMETER timeout
Maximum time (in msec) to transfer 1 File or run 1 command
.PARAMETER logfile
File to log output to (standard level is ERROR, set -info and/or -debuger for more output)
.PARAMETER insecure
Deactivate ssl certificate validation (needed for untrusted certificates)
.PARAMETER checkhash
Compare hash of local file with remote file (if it exists), do not upload if remotefile has same hash
.PARAMETER size
Display folder size in listings (takes time...)
.EXAMPLE
.\psswift.ps1 list files/ -recurse -size -format
List files in folder
.EXAMPLE
.\psswift.ps1 upload .\testfile.txt  files/examples/testfile.txt -checkhash
upload single file only if this exact file does not exist on target location
.EXAMPLE
.\psswift.ps1 upload_archive files.tar.gz files/
Upload file end extract remotely
.EXAMPLE
.\psswift.ps1 upload_folder .\localfiles\ files/ -checkhash
Upload folder
.EXAMPLE
.\psswift.ps1 download files/examples.txt .\examples.txt
Download single file
.EXAMPLE
.\psswift.ps1 download_folder files/ .\localfiles\
Downlowd whole folder
.EXAMPLE
.\psswift.ps1 delete files/ -recurse
Delete remote folder
.EXAMPLE
.\psswift.ps1 delete files/example.txt
Delete remote file

#>

##
## https://gist.github.com/drewkerrigan/2876196

param (
	[ValidateSet('token','url','list','ls','copy','upload','upload_archive','backup','upload_folder','download','delete')][Parameter(Mandatory=$false,Position=0,ParameterSetName='list')][Parameter(Mandatory=$True,Position=0,ParameterSetName='download')][string]$command,
	[Parameter(Position=1,ParameterSetName='list')][Parameter(Mandatory=$True,Position=1,ParameterSetName='download')][string]$source,
	[Parameter(Position=2,Mandatory=$True,ParameterSetName='download')][string]$destination,
	[Parameter(ParameterSetName='list')][Parameter(Position=3,ParameterSetName='download')][switch]$recurse,
	
	# Auth parameters

	[string]$storage_url = "https://MYSTORAGE:443/v1/AUTH_TOKEN",
	[string]$auth_url = "http://MYAUTH:5000/v3/auth/tokens",
	[string]$username = "username",
	[string]$password = "password",
	[string]$tenant = "tenant",
	[string]$container = "container",

	[string]$uploadlog,
	[string]$timeout = 1000*60*30, #30min timeout
	[string]$logfile,
	[string]$tempPath = "c:\Temp\",
	[switch]$show_connect_string,
	[switch]$insecure = $true,
	[switch]$checkhash,
	[switch]$info,
	[switch]$debuger,
	[Parameter(ParameterSetName='list')][switch]$size,
	[Parameter(ParameterSetName='list')][switch]$format,
	[int]$splitsize = 1024*1024*10,
	[string]$failed_csv_file = "failed.csv"
	
)
$STATIC_LARGE_FILE_SUPPORT = $True
$backup_destination = "backup"


function log() {
	param(
		[string] $message,
		[string] $level = "info",
		[string] $mycommand = $command.ToUpper()
	)
	$time = Get-Date -format "dd MMM yyyy HH:mm:ss"
	switch ($level) {
		"info" {
			write-host "$time INFO $command $message"
			if ($info -and $logfile) {	"$time INFO $command $message" | out-file $logfile -append}
			break
		}
		"error" {
			write-host "$time ERROR $command $message" -foreground red
			if ($logfile) {	"$time ERROR $command $message" | out-file $logfile -append}
			break
		}
		"warn" {
			write-host "$time WARN $command $message" -foreground Magenta
			if ($logfile) {	"$time WARN $command $message" | out-file $logfile -append}
			break
		}
		"debug" {
			if ($debuger){
				write-host "$time DEBUG $command $message" -foreground red
				if ($logfile) {	"$time DEBUG $command $message" | out-file $logfile -append}
				break
			}
		}
		"connect" {
			if ($show_connect_string){
				write-host "$time CONNECT $message" -foreground green
				break
			}
		}
		"uploadlog" {
			$script:upload_log += "$message`n"
			break
		}
		"csv" {
			if ($failed_csv_file){
				"$message" | out-file $failed_csv_file -append
			}
			break
		}
		"fatal" {
			write-host "$time FATAL $command $message - EXITING" -foreground darkred
			if ($logfile) {	"$time FATAL $command $message - EXITING" | out-file $logfile -append}
			exit 1
		}
	}
	
}

function getToken {
	try {
		##  curl -s -D - -H "Content-Type:application/json" -XPOST http://178.22.65.9:5000/v3/auth/tokens -d '{"auth":{"identity":{"password":{"user":{"domain":{"id":"default"},"password":"ieV8eeJieQuaequ7","name":"picturepark"}},"methods":["password"]},"scope":{"project":{"name":"pictureparkproj","domain":{"id":"default"}}}}}' -o /dev/null | grep "X-Subject-Token"
		log "Invoke-WebRequest -Uri $auth_url -Body $auth_json -ContentType application/json -Method post" "connect"
		$res=Invoke-WebRequest -Uri $auth_url -Body $auth_json -ContentType application/json -Method post
		$script:token=$res.headers['X-Subject-Token']
	} catch {
		log "$($_.exception.message)" "fatal"
	}
}

function initialize() {
	$script:auth_json = '{
	"auth": {
			"identity": {
				"password": {
					"user": {
						"domain": {
							"id": "default"
						},
						"password": "'+$password+'",
						"name": "'+$username+'"
					}
				},
				"methods": [
					"password"
				]
						},
			"scope": {
			  "project": {
				"name": "'+$tenant+'",
				"domain": { "id": "default" }
			  }
			}
		}
	}' 

	$script:ssl_workaround = "
		using System.Collections.Generic;
		using System.Net;
		using System.Net.Security;
		using System.Security.Cryptography.X509Certificates;

		public static class SSLValidator
		{
			private static Stack<System.Net.Security.RemoteCertificateValidationCallback> funcs = new Stack<System.Net.Security.RemoteCertificateValidationCallback>();

			private static bool OnValidateCertificate(object sender, X509Certificate certificate, X509Chain chain,
														SslPolicyErrors sslPolicyErrors)
			{
				return true;
			}

			public static void OverrideValidation()
			{
				funcs.Push(ServicePointManager.ServerCertificateValidationCallback);
				ServicePointManager.ServerCertificateValidationCallback =
					OnValidateCertificate;
			}

			public static void RestoreValidation()
			{
				if (funcs.Count > 0) {
					ServicePointManager.ServerCertificateValidationCallback = funcs.Pop();
				}
			}
		}
	"
	
	$script:extended_webclient = @"
		using System;
		using System.Net;

		public class WebDownload : WebClient
		{
			/// <summary>
			/// Time in milliseconds
			/// </summary>
			public int Timeout { get; set; }

			public WebDownload() : this(60000) { }

			public WebDownload(int timeout)
			{
				this.Timeout = timeout;
			}

			protected override WebRequest GetWebRequest(Uri address)
			{
				var request = base.GetWebRequest(address);
				if (request != null)
				{
					request.Timeout = this.Timeout;
				}
				return request;
			}
		}
"@;

}

Function Format-FileSize() {
    Param ([int64]$size)
    If     ($size -gt 1TB) {[string]::Format("{0:0.00} TB", $size / 1TB)}
    ElseIf ($size -gt 1GB) {[string]::Format("{0:0.00} GB", $size / 1GB)}
    ElseIf ($size -gt 1MB) {[string]::Format("{0:0.00} MB", $size / 1MB)}
    ElseIf ($size -gt 1KB) {[string]::Format("{0:0.00} kB", $size / 1KB)}
    ElseIf ($size -gt 0)   {[string]::Format("{0:0.00} B", $size)}
    Else                   {""}
}

function Format-UnixTime () {
	param ($unixtime)
	$currenttime = [timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($unixtime))
	return $currenttime
}

function splitFile(){
	param (
		$inFile,
		$check = $false
	)
	log "Splitting file $inFile"
	$stream = [System.IO.File]::OpenRead($($inFile.fullname))
	$chunkNum = 1
	$barr = New-Object byte[] $splitsize  
	$outfiles = @()
	while( $bytesRead = $stream.Read($barr,0,$splitsize )){
		$obj = New-Object PSObject
		$outFile = "$tempPath$($inFile.name)$($chunkNum.ToString(""000000""))"
		$ostream = [System.IO.File]::OpenWrite($outFile)
		$ostream.Write($barr,0,$bytesRead);
		$ostream.close();
		$file = get-item $outfile
		$obj | Add-Member NoteProperty local_path("$outFile")
		$obj | Add-Member NoteProperty etag(((Get-FileHash $file -Algorithm MD5).hash).ToLower())
		$obj | Add-Member NoteProperty size_bytes("$($file.Length)")
		$obj | Add-Member NoteProperty remote_path("")
		$obj | Add-Member NoteProperty name("$($inFile.name)$($chunkNum.ToString(""000000""))")
		$outfiles += $obj
		$chunkNum += 1
	}
	
	if ($check){
		$md5 = Get-FileHash $($inFile.fullname) -Algorithm MD5
		$outFile = "$tempPath$($inFile.name).verify"
		New-Item -ItemType file $outFile -force | out-null
		$filesToCopy = ""
		for ($i = 1; $i -lt $chunkNum; $i++){
			if ($i -gt 1) { $filesToCopy = "$filesToCopy`+"}
			$filesToCopy = "$filesToCopy$tempPath$($inFile.name)$($i.ToString(""000000""))"
		}
		$blubb = cmd.exe /C copy /b $filesToCopy $outfile
		$md5_verify = Get-FileHash $outFile -Algorithm MD5
		if ($md5.hash -ne $md5_verify.hash){
			log "Could not verify File $($inFile.fullname)" "error"
		} 
		remove-Item $outFile -force | out-null
	}
	
	
	return @($outfiles)
}

function getData () {
	param (
		[string]$request,
		[string]$method = "get",
		[switch]$rest = $false,
		[hashtable]$headers,
		[string]$body
	)
	log "getData" "debug"
	$myHeaders = @{}
	$myHeaders += @{"X-Auth-Token"="$token"}
	if ($headers){
		$myHeaders += $headers
	}
	try {
		$connect_string = ""
		if ($rest){
			$connect_string = "Invoke-RestMethod -uri ""$request"" -headers $myHeaders -timeout $timeout -Method $method"
			log $connect_string "connect"
			$res = Invoke-RestMethod -uri "$request" -headers $myHeaders -timeout $timeout -Method $method 
		}else {
			if ($body){
				$connect_string = "Invoke-WebRequest -uri ""$request"" -headers $myHeaders -timeout $timeout -Method $method -body $body"
				log $connect_string "connect"
				$res = Invoke-WebRequest -uri "$request" -headers $myHeaders -timeout $timeout -Method $method -body $body
			} else {
				$connect_string = "Invoke-WebRequest -uri ""$request"" -headers $myHeaders -timeout $timeout -Method $method"
				log $connect_string "connect"
				$res = Invoke-WebRequest -uri "$request" -headers $myHeaders -timeout $timeout -Method $method
			}
		}
	} catch {
		$e=$_.exception.message
		$e="$e`nRequest: $connect_string"
		throw $e
	}
	log "getData:res=$res" "debug"
	return $res
}

function getStaticLargeFileJson (){
	param(
		$files
	)
	[string]$json = ""
	$json = "$json["
	foreach ($file in $files){
		$json = "$json{"
		$json = "$json""path"": ""$($file.path)"","
		$json = "$json""etag"": ""$($file.etag)"","
		$json = "$json""size_bytes"": $($file.size_bytes)"
		$json = "$json}"
		$json = "$json,"
	}
	$json = $json.substring(0,($json.length-1))
	$json = "$json]"
	return $json

}

function getType () {
	param (
		$source
	)
	$hasSlash = $false
	if ($source.substring($source.length-1) -eq "/"){
		$hasSlash = $true
		$request = "$storage_url/$container/?prefix=$source`&delimiter=/&format=json" 
		$res = getData $request -rest:$true
		if ($res.count -gt 0){
			return "Folder"
		}
		$source = $source.substring(0,$source.length-1)
		
	}
	$request = "$storage_url/$container/?prefix=$source`&delimiter=/&format=json" 

	$res = getData $request -rest:$true
	foreach ($ele in $res) {
		$name = "$($ele.name)"
		$subdir="$($ele.subdir)"
		if ($ele.subdir -and ($subdir -eq "$source/")){
			log "$source is Folder" "debug"
			return "Folder"

		} 
		if ($name -eq "$source"){
		log "$source is file" "debug"
			return "File"
		}
	}
	log "$source is unknown" "debug"
	return "unknown"
}

function getRemoteHash () {
	param ([string] $remoteFile)
	$remoteFile = $remoteFile.replace("\","/")
	try {
		$res = getData "$storage_url/$container/$remoteFile" -method "head"
	} catch {
		$e = $_.exception.message
		if ($e -like "*404*"){
			return "0"
		}
		log "Exception: $e" "error"
	}
	return 	($res.headers).etag
}

function list_files() {
	param (
		[string]$source,
		[switch]$recurse
	)
	$request = "$storage_url/$container/"
	$method = "get"
	$rest = $true
	$type = ""
	if ($source) {
		$type = getType($source)
		if ($type -eq "unknown"){
			log "File $source not found" "error"
			return @()
		}
		if (($type -eq "Folder")){
			if ($source.substring($source.length-1) -ne "/") {
				$source = "$source/"
			}
			$request = "$request`?prefix=$source&format=json"
			if ((-not $recurse)) {
				$request = "$request`&delimiter=/"
			}
				
		}
		if ($type -eq "file"){
			$request = "$request$source"
			$method = "head"
			$rest = $false
		}
		

	} else {
		if ($recurse) {
			$request = "$request`?format=json"
		} else {
			$request = "$request`?delimiter=/&format=json"
		}
	}

	$res = getData $request -rest:$rest -method $method 
	$fileList = @()
	$sloList = @()
	foreach ($item in $res){
		if ($item.subdir) 
		{
			$obj = New-Object PSObject
			$obj | Add-Member NoteProperty Type("Dir")
			$obj | Add-Member NoteProperty Name($item.subdir)
			$obj | Add-Member NoteProperty Size("")
			$obj | Add-Member NoteProperty Hash("")
			$fileList += $obj
		}
	}
	foreach ($item in $res){
		if ($item.hash) {
			$obj = New-Object PSObject
			$obj | Add-Member NoteProperty Type("File")
			$obj | Add-Member NoteProperty Name($item.name)
			if ($item.bytes -eq 0){
				$res = getData "$storage_url/$container/$($item.name)" -method "head"
				$obj | Add-Member NoteProperty Size($res.headers['Content-Length'])
			} else {
				$obj | Add-Member NoteProperty Size($item.bytes)
			}
			$obj | Add-Member NoteProperty Hash($item.hash)
			$fileList += $obj
		} elseif (-not $item.subdir){
			$obj = New-Object PSObject
			$obj | Add-Member NoteProperty Type("File")
			$obj | Add-Member NoteProperty Name($source)
			$obj | Add-Member NoteProperty Size($item.headers['Content-Length'])
			$obj | Add-Member NoteProperty Hash($item.headers['ETag'])
			$obj | Add-Member NoteProperty Last_Modified([datetime]$item.headers['Last-Modified'])
			$obj | Add-Member NoteProperty Timestamp($item.headers['X-Timestamp'])
			$obj | Add-Member NoteProperty Content-Type($item.headers['Content-Type'])
			if ($item.headers['X-Static-Large-Object'] -eq "True"){
				$obj | Add-Member NoteProperty SLO($true)
				$sloList += $obj
			} else{
				$obj | Add-Member NoteProperty SLO($false)
			}
			$fileList += $obj
		}
	}
	foreach ($slo in $sloList){
		log $slo.name
	}
	return $fileList
}

function upload_file() {
	param($source,$destination,$archive)
	if (-not $source) { 
		log "no source defined" "error"
		return 1
	}
	if (-not $destination) { 
		log "No destination defined for source $source" "error"
		return 1
	}
	$wc = New-Object WebDownload
	$wc.Timeout = $script:timeout
	$wc.Headers.add("X-Auth-Token","$token")
	$destination = $destination.Replace("\","/")
	if ($archive){
		$dirchar = $destination.substring($destination.length - 1)
		if (-not ($dirchar -eq "/")){ throw "Destination must be directory (ending with /)"}
		$uploadpath = "$storage_url/$container/$destination`?extract-archive=tar$archive"
	} else {
		if ($script:checkhash){
			$remotehash = getRemoteHash $destination
			if ($remotehash) {
				$hash = Get-FileHash $source -Algorithm MD5
				if ($($hash.Hash) -eq $remotehash) {
					log "skipping $destination, already there"
					log "$container/$destination" "uploadlog"
					return 0
				}
			}
		}
		log "uploading $destination"
		$uploadpath = "$storage_url/$container/$destination"
		if ($(get-item $source).Length -gt $splitsize  ){
			$parts = splitFile (get-item $source) $true
			if ($script:STATIC_LARGE_FILE_SUPPORT){
				$jsondefs = @()
				$i = 0
				foreach ($file in $parts){
					$i++
					Write-Progress -Id 1 -activity "Uploading chunks" -status "Chunk $i of $($parts.count)" -PercentComplete (($i / $parts.Count)  * 100)
					$res = $wc.UploadFile("$uploadpath/$($file.name)","put","$($file.local_path)")
					$obj = New-Object PSObject
					$obj | Add-Member NoteProperty path("$container/$destination/$($file.name)")
					$obj | Add-Member NoteProperty etag("$($file.etag)")
					$obj | Add-Member NoteProperty size_bytes($($file.size_bytes))
					$jsondefs += $obj
					remove-item $($file.local_path)
				}
				$json = getStaticLargeFileJson $jsondefs
				$res=getData "$uploadpath`?multipart-manifest=put" -body $json -method "put"
			} else {
				foreach ($file in $parts){
					$res = $wc.UploadFile("$uploadpath/$($file.name)","put","$($file.local_path)")
					remove-item $($file.local_path)
				}
				$wc.Headers.add("X-Object-Manifest","$container/$destination/$((get-item $source).name)")
				$res = $wc.UploadFile("$uploadpath","put",(New-Item $tempPath`empty -ItemType file -force))
			}
		} else {
			try{
				$res = $wc.UploadFile("$uploadpath","put","$source")
			} catch [System.Net.WebException]{
				$code = $((($_.Exception).Response).StatusCode)
				if ($code -eq 401){
					log "Lost token" "error"
					getToken
					$wc = New-Object WebDownload
					$wc.Timeout = $script:timeout
					$wc.Headers.add("X-Auth-Token","$token")

					try{
						$res = $wc.UploadFile("$uploadpath","put","$source")
					}
					catch {
						log "Upload failed: $source" "error"
						return 1

					}
				} else {
					log "Upload failed: $source" "error"
					return 1
				}
			}
		}
	}
	$wc.close
	return 0
}

function download_file() {
	param($source, $destination)
	if (-not ($destination)){
		throw "No destination parameter provided"
	}
	new-item $destination -type file -force | out-null
	$destination = (get-item $destination).fullname
	$wc = New-Object WebDownload
	$wc.Timeout = $script:timeout
	$wc.Headers.add("X-Auth-Token","$token")
	log "downloading $storage_url/$container/$source to $destination"
	try {
		$wc.Downloadfile("$storage_url/$container/$source", $destination)
	} catch [System.Net.WebException]{
		$code = $((($_.Exception).Response).StatusCode)
		if ($code -eq 401){
			log "Lost token" "error"
			getToken
			$wc = New-Object WebDownload
			$wc.Timeout = $script:timeout
			$wc.Headers.add("X-Auth-Token","$token")
			try{
				$wc.Downloadfile("$storage_url/$container/$source", $destination)
			}
			catch {
				log "Download failed: $source" "error"
				return "error"
			}
		} else {
			log "Download failed: $source" "error"
			return "error"
		}
	}

}

function delete_file() {
	param (
		$source,
		$recurse
		)
	log "Deleting $source"
	$request = "$storage_url/$container/"
	if ($recurse) {
		$request = "$request`?bulk-delete"
		$files = @(list_files "$source" -recurse)
		if ($files){
			log "deleting $($files.count) files"
			$file_list = @()
			foreach ($file in $files) {
				$file_list += "$container/$($file.name)`n"
			}
			getData $request -method "delete" -body "$file_list"
		}
	} else {
		$request = "$request$source"
		$res=getData $request -method "head"
		if ($res.headers['X-Static-Large-Object'] -eq "True"){
			$request = "$request`?multipart-manifest=delete"
		}
		$res = getData $request -method "delete"
	}
	return 0
}

function sendRequest() {
	param (
		[string]$command = $script:command,
		[string]$source = $script:source,
		[string]$destination = $script:destination
	)
	if ($script:insecure){[SSLValidator]::OverrideValidation(); }
		switch ($command.ToLower()){
			backup {
				if (-not ($source)) {throw "Source CSV required for backups"}
				if (-not $destination) { throw "Destination needed (root path of files)"}
				if ($destination.substring($destination.length -1) -ne "\"){
					$destination = "$destination\"
				}
				$csvfile = Get-Item $source
				if (-not ($csvfile)){
					log "CSV-File not found" "fatal"
				}
				$files = import-csv $source ";" -Header "PATH","SIZE","MODE"
				#new-item "$($csvfile.directoryname)\archive" -ErrorAction SilentlyContinue)
				#copy-item $csvfile "$($csvfile.directoryname)\archive\$($csvfile.name)"
				$copiedSize = 0
				$totalSize = 0
				$line = 0
				foreach ($file in $files ){
					if ($file.mode -ne "DELETE"){
						$totalSize += $file.size /1MB
					}
				}
				$totalSize =  [math]::Round($totalSize)
				foreach ($file in $files){
					$line++
					Write-Progress -Id 0 -activity "Working on $source" -status "Copied $copiedSize of $totalSize MB, File $line of $($files.count)" -PercentComplete (($copiedSize / $totalSize)  * 100)
					switch ($($file.MODE).ToUpper()){
						"CREATE" {
							$src = (get-item $file.path -ErrorAction SilentlyContinue)
							if (-not $src) {
								log "File $($file.path) not found" "error"
								log "$($file.path);$($file.size);$($file.mode)" "csv"
								continue
							}
							if ($src.length -ne $file.size){
								log "Size for $($src.fullname) not matching, is $($src.length), should be $($file.size)" "warn"
								log "$($file.path);$($file.size);$($file.mode)" "csv"

							}
							$start = "$destination".length
							$target = "$backup_destination/$($($src.fullname).substring($start))"
							$res = upload_file "$($src.fullname)" "$target"
							if ($res -ne 0){
								log "$($file.path);$($file.size);$($file.mode)" "csv"
							} 
							if ($src.length -le $splitsize) {
								$remotehash = getRemoteHash $target
								$hash = Get-FileHash $src -Algorithm MD5
							} 
							if ((($($hash.Hash) -ne $remotehash) -and ($src.length -le $splitsize))) {
								log "Hash of uploaded file $($src.fullname) does not match calculated Hash" "warn"
								log "$($file.path);$($file.size);$($file.mode)" "csv"
							}
						}
						"MODIFY" {
							
						}
						"DELETE" {
							$src = $file.path
							$start = "$destination".length
							$target = "$backup_destination/$($src.substring($start))"
							try {
								$res = delete_file "$($target)"
							} catch {
								$exception = $($_.exception.message)
								log "$exception" "warn"
								if ($exception -like "*404*") {
									log "Failed to delete File $src`: File not found" "Error"
								} else {
									log "Failed to delete File $src" "Error"
								}
								$res = 1
							}
							if ($res -ne 0){
								log "$($file.path);$($file.size);$($file.mode)" "csv"
							} 
						}
					}
					if ($file.mode -ne "DELETE"){
						$copiedSize += $file.size /1MB
					}
					$copiedSize =  [math]::Round($copiedSize)
				}
				break
			}
			copy {
				$headers=@{"X-Copy-From"="$container/$source"}
				$res = getData "$storage_url/$container/$destination" -method "put" -headers $headers
				break
			}
			delete {
				if (-not ($source)) {throw "Source required for delete"}
				delete_file $source -recurse $script:recurse
				break
			}
			download {
				if ($recurse){
					if (-not ($source)) {
						log "Source required for folder downloads" "fatal"
					}
					if (-not ((getType $source) -eq "Folder")){
						log "Source must be a folder" "fatal"
					}
					if ($source.substring($source.length-1) -ne "/"){
						$source = "$source/"
					}
					if (-not ($destination)) {
						log "Destination required for folder downloads" "fatal"
						}
					if (-not (Test-Path $destination)){
						mkdir $destination | out-null
					} 
					if (-not ((get-item $destination) -is [System.IO.DirectoryInfo])){
						log "Destination must be a folder" "fatal"
					}
					
					$destination = (get-item $destination -ErrorAction SilentlyContinue).fullname
					if (-not ($destination.substring($destination.Count-1) -eq "\")){
						$destination = "$destination`\"
					}
					$files = @(list_files "$source" -recurse)
					$i = 0
					foreach ($file in $files){
						$target = (($file.name).substring($source.length)).replace("/","\")
						download_file $file.name  "$destination$target"
						$i++
						Write-Progress -Id 0 -activity "Downloading  Files" -status "Percent downloaded: (($i / $files.Count)  * 100)" -PercentComplete (($i / $files.Count)  * 100)
					}

				} else {
					if (-not $source) {
						log "Source required for file downloads" "fatal"
					}
					if (getType $source -ne "File"){
						log "Source must be file for file downloads - use -recurse for directory downloads" "fatal"
					}
					if (-not $destination){
						log "Destination required for file downloads" "fatal"
					}
					download_file "$source" "$destination"
				}
				break
				}
			{$_ -in "list","ls"} {
				$files = list_files "$source" -recurse:$script:recurse
				if ($size){
					foreach ($file in $files){
						if ($file.type -eq "Dir"){
							$file.Size = 0
							$files_sub = list_files $file.name -recurse
							foreach ($file_sub in $files_sub) {
								$file.Size = $file.Size + $file_sub.Size
							}
						}
					}
				}
				if ($format) {
					foreach ($file in $files){
						if (($file.type -eq "File") -and ($files.count -eq "")){
							$file.Timestamp = Format-UnixTime $file.Timestamp
						}
						$file.size = Format-FileSize $file.Size
					}
				}
				$files
				
				break
			}
			token {log "auth_token=$token"; break}
			upload {
				$source = (get-item $source).fullname
				upload_file "$source" "$destination"
				break
			}
			upload_archive {
				log "uploading $source to $destination"
				$extn = [IO.Path]::GetExtension($source)
				if (-not (($extn -eq ".gz" ) -or ($extn -eq ".bz2")))
				{
					throw "Extension needs to be gz or bz2"
				}
				upload_file "$source" "$destination" "$extn"
				break
			}
			upload_folder {
				## check $source
				if (-not ($source)) {
					log "Source required for folder uploads" "error"
					return 1
				}
				if (Test-Path $source){
					if (-not ((get-item $source) -is [System.IO.DirectoryInfo])) {log "source must be a directory" "error"; return 1}
					$source = (get-item $source -ErrorAction SilentlyContinue).fullname 
				} else {
					log "Folder $source does not exist on the Filesystem" "error"
					return 1
				}
				if (-not ($destination)) {log "Destination required for folder uploads" "error"}
				$dirchar = $source.substring($source.length - 1)
				if (-not ($dirchar -eq "\")){ $source = $source+"\" }
				$dirchar = $destination.substring($destination.length - 1)
				if (-not ($dirchar -eq "/")){ $destination = $destination+"/" }

				
				$files = Get-ChildItem $source -recurse -file
				
				$i = 0
				foreach ($file in $files) {
					$filedestination = (($file.fullname).substring($source.length)).Replace("\","/")
					upload_file "$($file.fullname)" "$destination$filedestination" 
					$i++
					Write-Progress -Id 0 -activity "Uploading  Files" -status "Percent uploaded: " -PercentComplete (($i / $files.count)  * 100)
					
					log "$container/$destination$filedestination" "uploadlog"
				}
				break
			}
			default {
				log "Usage: help mySwitch -full"
				break
			}
		}
	if ($script:insecure){ [SSLValidator]::RestoreValidation();	}
}
initialize
$upload_log = ""
if ($info -and $logfile) {log "----------------------------------STARTING SESSION-----------------------------------------------" "info"}
Add-Type $ssl_workaround
if (-not ([System.Management.Automation.PSTypeName]'WebDownload').Type)
{
    Add-Type -TypeDefinition $extended_webclient -Language CSharp 
}

getToken

#log "got token, starting $command"
if (($command -eq "list") -or ($command -eq "backup") -or ($command -eq "copy") -or ($command -eq "download_folder") -or ($command -eq "ls") -or ($command -eq "info")){
	sendrequest
} else {
	$time=Measure-Command {sendrequest}
	log "Time taken: $time" 
}
if ($info -and $logfile) {log "----------------------------------ENDING SESSION-----------------------------------------------" "info"}
[SSLValidator]::RestoreValidation();
if ($uploadlog) {$upload_log | out-file $uploadlog -append}