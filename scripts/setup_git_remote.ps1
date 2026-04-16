param(
    [Parameter(Mandatory=$true)]
    [string]$RepoUrl
)

if (-not (Test-Path .git)) {
    git init
}
if ((git remote) -notcontains "origin") {
    git remote add origin $RepoUrl
} else {
    git remote set-url origin $RepoUrl
}
Write-Host "Remote 'origin' set to:" $RepoUrl
