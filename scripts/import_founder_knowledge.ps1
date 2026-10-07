[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [string]$BaseUrl = $env:EFATA777_API_BASE_URL,
    [string]$KnowledgeFile = (Join-Path $PSScriptRoot "knowledge\EFATA777_FOUNDER_PROFILE_DANIEL_GRAEBIN_v1_3.md"),
    [string]$AgentId = "orkio",
    [switch]$Apply,
    [switch]$Publish
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ExpectedSha256 = "1a6f9ffae454ef310c0be07381dcb530a0d3e711b9df71acce8584f70aaaaedd"
$Scope = "INSTITUTIONAL"
$Classification = "internal"
$AllowedPurposes = "chat,team,realtime"
$ProductName = "EFAT$([char]0x00C0) 777"
$EmDash = [char]0x2014
$Title = "$ProductName $EmDash Founder Profile $EmDash Daniel Graebin"

function Get-ResponseBody {
    param([System.Net.Http.HttpResponseMessage]$Response)
    return $Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
}

function Assert-Success {
    param(
        [System.Net.Http.HttpResponseMessage]$Response,
        [string]$Operation
    )
    if (-not $Response.IsSuccessStatusCode) {
        $body = Get-ResponseBody -Response $Response
        throw "$Operation failed: HTTP $([int]$Response.StatusCode) $($Response.ReasonPhrase). Body=$body"
    }
}

if (-not (Test-Path -LiteralPath $KnowledgeFile -PathType Leaf)) {
    throw "Knowledge file not found: $KnowledgeFile"
}

$resolvedFile = (Resolve-Path -LiteralPath $KnowledgeFile).Path
$actualHash = (Get-FileHash -LiteralPath $resolvedFile -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -ne $ExpectedSha256) {
    throw "Knowledge file SHA256 mismatch. Expected=$ExpectedSha256 Actual=$actualHash"
}

Write-Host "EFATA777_FOUNDER_KNOWLEDGE=VALIDATED"
Write-Host "FILE=$resolvedFile"
Write-Host "SHA256=$actualHash"
Write-Host "SCOPE=$Scope"
Write-Host "CLASSIFICATION=$Classification"
Write-Host "AGENT_ID=$AgentId"
Write-Host "ALLOWED_PURPOSES=$AllowedPurposes"

if (-not $Apply) {
    Write-Host "MODE=VALIDATE_ONLY"
    Write-Host "No API write executed. Re-run with -Apply after the human gate."
    exit 0
}

if ([string]::IsNullOrWhiteSpace($BaseUrl)) {
    throw "Base URL is required. Use -BaseUrl or EFATA777_API_BASE_URL."
}
$BaseUrl = $BaseUrl.TrimEnd("/")

$token = $env:EFATA777_ACCESS_TOKEN
if ([string]::IsNullOrWhiteSpace($token)) {
    $secureToken = Read-Host "$ProductName access token" -AsSecureString
    $token = [System.Net.NetworkCredential]::new("", $secureToken).Password
}
if ([string]::IsNullOrWhiteSpace($token)) {
    throw "Access token is required."
}

if ($Publish -and -not $Apply) {
    throw "-Publish requires -Apply."
}

Add-Type -AssemblyName System.Net.Http

$client = [System.Net.Http.HttpClient]::new()
$client.Timeout = [TimeSpan]::FromSeconds(90)
$client.DefaultRequestHeaders.Authorization =
    [System.Net.Http.Headers.AuthenticationHeaderValue]::new("Bearer", $token)

try {
    $uploadUri = "$BaseUrl/api/v2/knowledge"
    if (-not $PSCmdlet.ShouldProcess($uploadUri, "Create DRAFT founder knowledge")) {
        Write-Host "UPLOAD=SKIPPED"
        exit 0
    }

    $form = [System.Net.Http.MultipartFormDataContent]::new()
    $form.Add([System.Net.Http.StringContent]::new($Scope), "scope")
    $form.Add([System.Net.Http.StringContent]::new($Title), "title")
    $form.Add([System.Net.Http.StringContent]::new($Classification), "classification")
    $form.Add([System.Net.Http.StringContent]::new($AllowedPurposes), "allowed_purposes")
    $form.Add([System.Net.Http.StringContent]::new($AgentId), "agent_id")

    $bytes = [System.IO.File]::ReadAllBytes($resolvedFile)
    $fileContent = [System.Net.Http.ByteArrayContent]::new($bytes)
    $fileContent.Headers.ContentType =
        [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("text/markdown")
    $form.Add($fileContent, "file", [System.IO.Path]::GetFileName($resolvedFile))

    $response = $client.PostAsync($uploadUri, $form).GetAwaiter().GetResult()
    Assert-Success -Response $response -Operation "Knowledge upload"

    $uploadBody = Get-ResponseBody -Response $response
    $uploaded = $uploadBody | ConvertFrom-Json

    if ($uploaded.status -ne "DRAFT") {
        throw "Unexpected upload status: $($uploaded.status). Expected DRAFT."
    }
    if ($uploaded.scope -ne $Scope) {
        throw "Unexpected scope: $($uploaded.scope). Expected $Scope."
    }
    if ($uploaded.agent_id -ne $AgentId) {
        throw "Unexpected agent_id: $($uploaded.agent_id). Expected $AgentId."
    }
    if ($uploaded.sha256.ToLowerInvariant() -ne $ExpectedSha256) {
        throw "Server SHA256 mismatch. Expected=$ExpectedSha256 Actual=$($uploaded.sha256)"
    }

    Write-Host "UPLOAD=DRAFT_CREATED"
    Write-Host "KNOWLEDGE_ID=$($uploaded.id)"
    Write-Host "LOGICAL_DOCUMENT_ID=$($uploaded.logical_document_id)"
    Write-Host "VERSION=$($uploaded.version)"

    if (-not $Publish) {
        Write-Host "PUBLISH=NOT_REQUESTED"
        Write-Host "Human review gate remains open."
        exit 0
    }

    $publishUri = "$BaseUrl/api/v2/knowledge/$($uploaded.id)/publish"
    if (-not $PSCmdlet.ShouldProcess($publishUri, "Publish founder knowledge DRAFT -> ACTIVE")) {
        Write-Host "PUBLISH=SKIPPED"
        exit 0
    }

    $emptyContent = [System.Net.Http.StringContent]::new("")
    $publishResponse = $client.PostAsync($publishUri, $emptyContent).GetAwaiter().GetResult()
    Assert-Success -Response $publishResponse -Operation "Knowledge publish"

    $publishBody = Get-ResponseBody -Response $publishResponse
    $published = $publishBody | ConvertFrom-Json

    if ($published.status -ne "ACTIVE") {
        throw "Unexpected publish status: $($published.status). Expected ACTIVE."
    }

    Write-Host "PUBLISH=ACTIVE"
    Write-Host "ACTIVE_KNOWLEDGE_ID=$($published.id)"
    Write-Host "ACTIVE_LOGICAL_DOCUMENT_ID=$($published.logical_document_id)"
    Write-Host "ACTIVE_VERSION=$($published.version)"
}
finally {
    $token = $null
    if ($client) { $client.Dispose() }
}
