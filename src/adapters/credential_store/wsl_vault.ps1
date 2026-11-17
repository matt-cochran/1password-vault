# opv's fixed script for Windows Credential Manager from WSL (spike S1 §5.3). It is passed
# whole with -EncodedCommand; nothing in it varies. Input is stdin only (never argv):
#   line 1: the operation (probe, get, set or delete)
#   line 2: the resource (opv)
#   line 3: the user name (account_id/project/env)
#   rest:   the value, for set only
# Output: for get, the value on stdout with no newline. Nothing else is written.
# Exit: 0 done, 3 no entry, 4 store failure, 5 unknown operation.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
  $utf8 = New-Object System.Text.UTF8Encoding $false
  [Console]::OutputEncoding = $utf8
  $in = New-Object System.IO.StreamReader([Console]::OpenStandardInput(), $utf8)
  $op = $in.ReadLine(); $res = $in.ReadLine(); $user = $in.ReadLine()
  [void][Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, ContentType = WindowsRuntime]
  $vault = New-Object Windows.Security.Credentials.PasswordVault
  if ($op -eq 'probe') { exit 0 }
  $found = $null
  try { $found = $vault.Retrieve($res, $user) } catch {
    $e = $_.Exception; while ($null -ne $e.InnerException) { $e = $e.InnerException }
    # 0x80070490, element not found: no entry. Anything else is a store failure.
    if ($e.HResult -ne -2147023728) { exit 4 }
  }
  switch ($op) {
    'get' {
      if ($null -eq $found) { exit 3 }
      $found.RetrievePassword()
      [Console]::Out.Write($found.Password)
      exit 0
    }
    'set' {
      $value = $in.ReadToEnd()
      if ($null -ne $found) { $vault.Remove($found) }
      $vault.Add((New-Object Windows.Security.Credentials.PasswordCredential($res, $user, $value)))
      exit 0
    }
    'delete' {
      if ($null -eq $found) { exit 3 }
      $vault.Remove($found)
      exit 0
    }
    default { exit 5 }
  }
} catch { exit 4 }
