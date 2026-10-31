# À exécuter sur chaque serveur Windows à superviser, après l'installation du SOC.
#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory=$true)][string]$Manager,
    [Parameter(Mandatory=$true)][string]$AgentName
)
$ErrorActionPreference = 'Stop'
$ip = $null
if (-not [System.Net.IPAddress]::TryParse($Manager, [ref]$ip)) { throw 'Adresse IP du SOC requise.' }
if ($AgentName -notmatch '^[a-zA-Z0-9_-]{1,64}$') { throw 'Nom agent invalide.' }
if (Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue) { throw 'Agent déjà présent : aucune réinstallation.' }
$msi = Join-Path $env:TEMP ('wazuh-' + [guid]::NewGuid().ToString('N') + '.msi')
Invoke-WebRequest -Uri 'https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.9-1.msi' -OutFile $msi
$sig = Get-AuthenticodeSignature -FilePath $msi
if ($sig.Status -ne 'Valid') { throw 'Signature MSI non valide : installation arrêtée.' }
$process = Start-Process msiexec.exe -ArgumentList @('/i', $msi, '/qn', "WAZUH_MANAGER=$Manager", "WAZUH_REGISTRATION_SERVER=$Manager", "WAZUH_AGENT_NAME=$AgentName") -Wait -PassThru
if ($process.ExitCode -notin @(0,3010)) { throw "Installation MSI échouée : $($process.ExitCode)" }
Start-Service WazuhSvc
Get-Service WazuhSvc
Write-Host 'Vérifier ensuite la connexion de cet agent dans le nouveau Wazuh.'
