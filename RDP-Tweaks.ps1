Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Check if running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    [System.Windows.Forms.MessageBox]::Show("This script requires Administrator privileges. Please run as Administrator.", "Administrator Required", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    exit
}

# Function to safely get registry value
function Get-RegistryValueSafe {
    param(
        [string]$Path,
        [string]$Name
    )
    try {
        $key = Get-Item -Path "Registry::$Path" -ErrorAction SilentlyContinue
        if ($key) {
            $value = Get-ItemProperty -Path "Registry::$Path" -Name $Name -ErrorAction SilentlyContinue
            if ($value) {
                return $value.$Name
            }
        }
        return $null
    } catch {
        return $null
    }
}

# Define registry modifications as objects with state checking
$registryMods = @(
    @{
        Name = "Optimize frame timing (DWMFRAMEINTERVAL) for Terminal Server"
        Enable = {
            reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations" /v "DWMFRAMEINTERVAL" /t REG_DWORD /d 0x0000000f /f 2>&1 | Out-Null
        }
        Disable = {
            reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations" /v "DWMFRAMEINTERVAL" /f 2>&1 | Out-Null
        }
        CheckState = {
            $value = Get-RegistryValueSafe -Path "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations" -Name "DWMFRAMEINTERVAL"
            if ($value -eq $null) { return "Disabled" }
            elseif ($value -eq 0x0f) { return "Enabled" }
            else { return "Indeterminate" }
        }
    },
    @{
        Name = "Set SystemResponsiveness to 0 for better performance"
        Enable = {
            reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 0x00000000 /f 2>&1 | Out-Null
        }
        Disable = {
            reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 0x00000014 /f 2>&1 | Out-Null
        }
        CheckState = {
            $value = Get-RegistryValueSafe -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness"
            if ($value -eq 0x00) { return "Enabled" }
            elseif ($value -eq 0x14 -or $value -eq $null) { return "Disabled" }
            else { return "Indeterminate" }
        }
    },
    @{
        Name = "Optimize flow control settings for TermDD service"
        Enable = {
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\TermDD" /v "FlowControlDisable" /t REG_DWORD /d 0x00000001 /f 2>&1 | Out-Null
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\TermDD" /v "FlowControlDisplayBandwidth" /t REG_DWORD /d 0x00000010 /f 2>&1 | Out-Null
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\TermDD" /v "FlowControlChannelBandwidth" /t REG_DWORD /d 0x00000090 /f 2>&1 | Out-Null
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\TermDD" /v "FlowControlChargePostCompression" /t REG_DWORD /d 0x00000000 /f 2>&1 | Out-Null
        }
        Disable = {
            reg delete "HKLM\SYSTEM\CurrentControlSet\Services\TermDD" /v "FlowControlDisable" /f 2>&1 | Out-Null
            reg delete "HKLM\SYSTEM\CurrentControlSet\Services\TermDD" /v "FlowControlDisplayBandwidth" /f 2>&1 | Out-Null
            reg delete "HKLM\SYSTEM\CurrentControlSet\Services\TermDD" /v "FlowControlChannelBandwidth" /f 2>&1 | Out-Null
            reg delete "HKLM\SYSTEM\CurrentControlSet\Services\TermDD" /v "FlowControlChargePostCompression" /f 2>&1 | Out-Null
        }
        CheckState = {
            $v1 = Get-RegistryValueSafe -Path "HKLM\SYSTEM\CurrentControlSet\Services\TermDD" -Name "FlowControlDisable"
            $v2 = Get-RegistryValueSafe -Path "HKLM\SYSTEM\CurrentControlSet\Services\TermDD" -Name "FlowControlDisplayBandwidth"
            $v3 = Get-RegistryValueSafe -Path "HKLM\SYSTEM\CurrentControlSet\Services\TermDD" -Name "FlowControlChannelBandwidth"
            $v4 = Get-RegistryValueSafe -Path "HKLM\SYSTEM\CurrentControlSet\Services\TermDD" -Name "FlowControlChargePostCompression"

            if ($v1 -eq $null -and $v2 -eq $null -and $v3 -eq $null -and $v4 -eq $null) {
                return "Disabled"
            }
            elseif ($v1 -eq 0x01 -and $v2 -eq 0x10 -and $v3 -eq 0x90 -and $v4 -eq 0x00) {
                return "Enabled"
            }
            else {
                return "Indeterminate"
            }
        }
    },
    @{
        Name = "Remove artificial latency delay (InteractiveDelay) in RDP"
        Enable = {
            reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "InteractiveDelay" /t REG_DWORD /d 0x00000000 /f 2>&1 | Out-Null
        }
        Disable = {
            reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "InteractiveDelay" /t REG_DWORD /d 0x00000032 /f 2>&1 | Out-Null
        }
        CheckState = {
            $value = Get-RegistryValueSafe -Path "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "InteractiveDelay"
            if ($value -eq 0x00) { return "Enabled" }
            elseif ($value -eq 0x32 -or $value -eq $null) { return "Disabled" }
            else { return "Indeterminate" }
        }
    },
    @{
        Name = "Optimize LanmanWorkstation network by disabling throttling and enabling large MTU"
        Enable = {
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableBandwidthThrottling" /t REG_DWORD /d 0x00000001 /f 2>&1 | Out-Null
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableLargeMtu" /t REG_DWORD /d 0x00000000 /f 2>&1 | Out-Null
        }
        Disable = {
            reg delete "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableBandwidthThrottling" /f 2>&1 | Out-Null
            reg delete "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableLargeMtu" /f 2>&1 | Out-Null
        }
        CheckState = {
            $v1 = Get-RegistryValueSafe -Path "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "DisableBandwidthThrottling"
            $v2 = Get-RegistryValueSafe -Path "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "DisableLargeMtu"

            if ($v1 -eq $null -and $v2 -eq $null) {
                return "Disabled"
            }
            elseif ($v1 -eq 0x01 -and $v2 -eq 0x00) {
                return "Enabled"
            }
            else {
                return "Indeterminate"
            }
        }
    },
    @{
        Name = "Use hardware graphics adapters for RDP"
        Enable = {
            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "bEnumerateHWBeforeSW" /t REG_DWORD /d 1 /f 2>&1 | Out-Null
        }
        Disable = {
            reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "bEnumerateHWBeforeSW" /f 2>&1 | Out-Null
        }
        CheckState = {
            $value = Get-RegistryValueSafe -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "bEnumerateHWBeforeSW"
            if ($value -eq $null) { return "Disabled" }
            elseif ($value -eq 1) { return "Enabled" }
            else { return "Indeterminate" }
        }
    },
    @{
        Name = "Enable RemoteFX/virtualized graphics"
        Enable = {
            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fEnableVirtualizedGraphics" /t REG_DWORD /d 1 /f 2>&1 | Out-Null
        }
        Disable = {
            reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fEnableVirtualizedGraphics" /f 2>&1 | Out-Null
        }
        CheckState = {
            $value = Get-RegistryValueSafe -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEnableVirtualizedGraphics"
            if ($value -eq $null) { return "Disabled" }
            elseif ($value -eq 1) { return "Enabled" }
            else { return "Indeterminate" }
        }
    },
    @{
        Name = "Allow RDP to use both UDP and TCP"
        Enable = {
            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "SelectTransport" /t REG_DWORD /d 2 /f 2>&1 | Out-Null
        }
        Disable = {
            reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "SelectTransport" /f 2>&1 | Out-Null
        }
        CheckState = {
            $value = Get-RegistryValueSafe -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "SelectTransport"
            if ($value -eq $null) { return "Disabled" }
            elseif ($value -eq 2) { return "Enabled" }
            else { return "Indeterminate" }
        }
    },
    @{
        Name = "Enable hardware H.264 encoding"
        Enable = {
            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AVCHardwareEncodePreferred" /t REG_DWORD /d 1 /f 2>&1 | Out-Null
        }
        Disable = {
            reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AVCHardwareEncodePreferred" /f 2>&1 | Out-Null
        }
        CheckState = {
            $value = Get-RegistryValueSafe -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "AVCHardwareEncodePreferred"
            if ($value -eq $null) { return "Disabled" }
            elseif ($value -eq 1) { return "Enabled" }
            else { return "Indeterminate" }
        }
    }
    @{
        Name = "Prioritize H.264/AVC 444 graphics mode"
        Enable = {
            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AVC444ModePreferred" /t REG_DWORD /d 1 /f 2>&1 | Out-Null
        }
        Disable = {
            reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AVC444ModePreferred" /f 2>&1 | Out-Null
        }
        CheckState = {
            $value = Get-RegistryValueSafe -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "AVC444ModePreferred"
            if ($value -eq $null) { return "Disabled" }
            elseif ($value -eq 1) { return "Enabled" }
            else { return "Indeterminate" }
        }
    },
    @{
        Name = "Enable Chrome Remote Desktop curtain mode"
        Enable = {
            reg add "HKLM\Software\Policies\Google\Chrome" /v "RemoteAccessHostRequireCurtain" /t REG_DWORD /d 1 /f 2>&1 | Out-Null
            reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d 0 /f 2>&1 | Out-Null
            reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "UserAuthentication" /t REG_DWORD /d 0 /f 2>&1 | Out-Null
            reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "SecurityLayer" /t REG_DWORD /d 1 /f 2>&1 | Out-Null
        }
        Disable = {
            reg delete "HKLM\Software\Policies\Google\Chrome" /v "RemoteAccessHostRequireCurtain" /f 2>&1 | Out-Null
            reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d 1 /f 2>&1 | Out-Null
            reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "UserAuthentication" /t REG_DWORD /d 1 /f 2>&1 | Out-Null
            reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "SecurityLayer" /t REG_DWORD /d 2 /f 2>&1 | Out-Null
        }
        CheckState = {
            $v1 = Get-RegistryValueSafe -Path "HKLM\Software\Policies\Google\Chrome" -Name "RemoteAccessHostRequireCurtain"
            $v2 = Get-RegistryValueSafe -Path "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
            $v3 = Get-RegistryValueSafe -Path "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication"
            $v4 = Get-RegistryValueSafe -Path "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer"

            if ($v1 -eq 1 -and $v2 -eq 0 -and $v3 -eq 0 -and $v4 -eq 1) {
                return "Enabled"
            }
            elseif ($v1 -eq $null -and $v2 -ne 0 -and $v3 -ne 0 -and $v4 -ne 1) {
                return "Disabled"
            }
            else {
                return "Indeterminate"
            }
        }
    }
)

# Ignore changes if this is false
$global:isAppEnabled = $false

# Create the main form
$form = New-Object System.Windows.Forms.Form
$form.Text = "RDP-Tweaks"
$form.Size = New-Object System.Drawing.Size(650, 745)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = 'FixedSingle'
$form.MaximizeBox = $false

# Create title label
$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Location = New-Object System.Drawing.Point(10, 10)
$titleLabel.Size = New-Object System.Drawing.Size(610, 30)
$titleLabel.Text = "RDP Performance Optimization Tweaks"
$titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$titleLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$form.Controls.Add($titleLabel)

# Create instruction label
$instructionLabel = New-Object System.Windows.Forms.Label
$instructionLabel.Location = New-Object System.Drawing.Point(10, 45)
$instructionLabel.Size = New-Object System.Drawing.Size(610, 35)
$instructionLabel.Text = "Check to enable the given optimization, uncheck to restore default setting (which may not necessarily disable it)."
$instructionLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$instructionLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$form.Controls.Add($instructionLabel)

# Create panel for checkboxes
$panel = New-Object System.Windows.Forms.Panel
$panel.Location = New-Object System.Drawing.Point(10, 85)
$panel.Size = New-Object System.Drawing.Size(610, 415)
$panel.AutoScroll = $true
$panel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$form.Controls.Add($panel)

# Create checkboxes for each registry modification
$checkBoxes = @()
$yPos = 10

foreach ($mod in $registryMods) {
    $checkBox = New-Object System.Windows.Forms.CheckBox
    $checkBox.Location = New-Object System.Drawing.Point(10, $yPos)
    $checkBox.Size = New-Object System.Drawing.Size(580, 30)
    $checkBox.Text = $mod.Name
    $checkBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $checkBox.Tag = $mod
    $checkBox.ThreeState = $true  # Enable three-state mode for indeterminate
    $checkBox.Enabled = $false

    # Add checkbox event handler
    $checkBox.Add_CheckStateChanged({
        $mod = $this.Tag

        # Ignore indeterminate state when user clicks
        if ($this.CheckState -eq [System.Windows.Forms.CheckState]::Indeterminate) {
            $this.CheckState = [System.Windows.Forms.CheckState]::Unchecked
            return
        }
        if (-not $global:isAppEnabled) {
            return
        }

        try {
            if ($this.CheckState -eq [System.Windows.Forms.CheckState]::Checked) {
                & $mod.Enable
                $statusLabel.Text = "Status: Enabled - $($mod.Name)"
                Write-Host "Enabled: $($mod.Name)"
            } else {
                & $mod.Disable
                $statusLabel.Text = "Status: Disabled - $($mod.Name)"
                Write-Host "Disabled: $($mod.Name)"
            }

            # Remove [Custom Value] text if it exists
            if ($this.Text.Contains("[Custom Value]")) {
                $this.Text = $this.Text.Replace(" [Custom Value]", "")
            }
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error applying setting: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    })

    $panel.Controls.Add($checkBox)
    $checkBoxes += $checkBox
    $yPos += 35
}

# Create GroupBox for Quality Settings
$qualityGroupBox = New-Object System.Windows.Forms.GroupBox
$qualityGroupBox.Location = New-Object System.Drawing.Point(10, 510)
$qualityGroupBox.Size = New-Object System.Drawing.Size(610, 80)
$qualityGroupBox.Text = "RemoteFX Quality Settings (Visual Experience, Frame Rate, Compression, Image Quality)"
$qualityGroupBox.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($qualityGroupBox)

# Function to check current quality settings state
$checkQualityState = {
    $v1 = Get-RegistryValueSafe -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "VisualExperiencePolicy"
    $v2 = Get-RegistryValueSafe -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "VGOptimization_CaptureFrameRate"
    $v3 = Get-RegistryValueSafe -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "VGOptimization_CompressionRatio"
    $v4 = Get-RegistryValueSafe -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "ImageQuality"
    $v5 = Get-RegistryValueSafe -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxCompressionLevel"

    if ($v1 -eq $null -and $v2 -eq $null -and $v3 -eq $null -and $v4 -eq $null -and $v5 -eq $null) {
        return "Disabled"
    }
    elseif ($v1 -eq 1 -and $v2 -eq 2 -and $v3 -eq 2 -and $v4 -eq 2 -and $v5 -eq 0) {
        return "HighQuality"
    }
    elseif ($v1 -eq 2 -and $v2 -eq 3 -and $v3 -eq 3 -and $v4 -eq 4 -and $v5 -eq 3) {
        return "LowQuality"
    }
    else {
        return "Custom"
    }
}

# Function to update quality settings
$setQualityState = {
    param([string]$State)

    switch ($State) {
        "Disabled" {
            try {
                reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "VisualExperiencePolicy" /f 2>&1 | Out-Null
                reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "VGOptimization_CaptureFrameRate" /f 2>&1 | Out-Null
                reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "VGOptimization_CompressionRatio" /f 2>&1 | Out-Null
                reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "ImageQuality" /f 2>&1 | Out-Null
                reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "MaxCompressionLevel" /f 2>&1 | Out-Null
                $statusLabel.Text = "Status: Quality settings disabled (defaults)"
                $customQualityLabel.Visible = $false
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Error disabling quality settings: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }
        "HighQuality" {
            try {
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "VisualExperiencePolicy" /t REG_DWORD /d 1 /f 2>&1 | Out-Null
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "VGOptimization_CaptureFrameRate" /t REG_DWORD /d 2 /f 2>&1 | Out-Null
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "VGOptimization_CompressionRatio" /t REG_DWORD /d 2 /f 2>&1 | Out-Null
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "ImageQuality" /t REG_DWORD /d 2 /f 2>&1 | Out-Null
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "MaxCompressionLevel" /t REG_DWORD /d 0 /f 2>&1 | Out-Null
                $statusLabel.Text = "Status: Applied High Quality settings"
                $customQualityLabel.Visible = $false
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Error applying high quality settings: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }
        "LowQuality" {
            try {
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "VisualExperiencePolicy" /t REG_DWORD /d 2 /f 2>&1 | Out-Null
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "VGOptimization_CaptureFrameRate" /t REG_DWORD /d 3 /f 2>&1 | Out-Null
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "VGOptimization_CompressionRatio" /t REG_DWORD /d 3 /f 2>&1 | Out-Null
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "ImageQuality" /t REG_DWORD /d 4 /f 2>&1 | Out-Null
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "MaxCompressionLevel" /t REG_DWORD /d 3 /f 2>&1 | Out-Null
                $statusLabel.Text = "Status: Applied Low Quality settings"
                $customQualityLabel.Visible = $false
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Error applying low quality settings: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }
    }
    Write-Host "Applied $State RemoteFX quality"
}

# Create status label
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Location = New-Object System.Drawing.Point(10, 645)
$statusLabel.Size = New-Object System.Drawing.Size(610, 20)
$statusLabel.Text = "Status: Ready - Current registry values loaded"
$statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)

# Create High Quality radio button
$highQualityRadio = New-Object System.Windows.Forms.RadioButton
$highQualityRadio.Location = New-Object System.Drawing.Point(20, 25)
$highQualityRadio.Size = New-Object System.Drawing.Size(140, 40)
$highQualityRadio.Text = "High Quality`n(Rich multimedia)"
$highQualityRadio.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$highQualityRadio.Enabled = $false
$highQualityRadio.Add_CheckedChanged({
    if (-not $global:isAppEnabled) {
        return
    }
    if ($highQualityRadio.Checked) {
        & $setQualityState -State "HighQuality"
    }
})
$qualityGroupBox.Controls.Add($highQualityRadio)

# Create Low Quality radio button
$lowQualityRadio = New-Object System.Windows.Forms.RadioButton
$lowQualityRadio.Location = New-Object System.Drawing.Point(180, 25)
$lowQualityRadio.Size = New-Object System.Drawing.Size(140, 40)
$lowQualityRadio.Text = "Low Quality`n(Text optimized)"
$lowQualityRadio.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$lowQualityRadio.Enabled = $false
$lowQualityRadio.Add_CheckedChanged({
    if (-not $global:isAppEnabled) {
        return
    }
    if ($lowQualityRadio.Checked) {
        & $setQualityState -State "LowQuality"
    }
})
$qualityGroupBox.Controls.Add($lowQualityRadio)

# Create Disabled radio button
$disabledRadio = New-Object System.Windows.Forms.RadioButton
$disabledRadio.Location = New-Object System.Drawing.Point(340, 25)
$disabledRadio.Size = New-Object System.Drawing.Size(140, 40)
$disabledRadio.Text = "Disabled`n(System default)"
$disabledRadio.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$disabledRadio.Enabled = $false
$disabledRadio.Add_CheckedChanged({
    if (-not $global:isAppEnabled) {
        return
    }
    if ($disabledRadio.Checked) {
        & $setQualityState -State "Disabled"
    }
})
$qualityGroupBox.Controls.Add($disabledRadio)

# Create custom value label for quality settings
$customQualityLabel = New-Object System.Windows.Forms.Label
$customQualityLabel.Location = New-Object System.Drawing.Point(490, 35)
$customQualityLabel.Size = New-Object System.Drawing.Size(100, 20)
$customQualityLabel.Text = "[Custom Values]"
$customQualityLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$customQualityLabel.Visible = $false
$qualityGroupBox.Controls.Add($customQualityLabel)

$refreshAppState = {
    $enableApp = {
        param([bool]$Enabled)

        $global:isAppEnabled = $Enabled

        foreach ($cb in $checkBoxes) {
            $cb.Enabled = $Enabled
        }
        $highQualityRadio.Enabled = $Enabled
        $lowQualityRadio.Enabled = $Enabled
        $disabledRadio.Enabled = $Enabled
    }

    $statusLabel.Text = "Status: Refreshing..."
    & $enableApp -Enabled $false

    # Refresh checkboxes
    foreach ($cb in $checkBoxes) {
        $mod = $cb.Tag
        $currentState = & $mod.CheckState

        # Remove existing [Custom Value] text before updating
        if ($cb.Text.Contains("[Custom Value]")) {
            $cb.Text = $cb.Text.Replace(" [Custom Value]", "")
        }

        switch ($currentState) {
            "Enabled" {
                $cb.CheckState = [System.Windows.Forms.CheckState]::Checked
            }
            "Disabled" {
                $cb.CheckState = [System.Windows.Forms.CheckState]::Unchecked
            }
            "Indeterminate" {
                $cb.CheckState = [System.Windows.Forms.CheckState]::Indeterminate
                $cb.Text += " [Custom Value]"
            }
        }
    }

    # Check and set initial quality state
    $currentQualityState = & $checkQualityState
    $highQualityRadio.Checked = $false
    $lowQualityRadio.Checked = $false
    $disabledRadio.Checked = $false
    $customQualityLabel.Visible = $false
    switch ($currentQualityState) {
        "HighQuality" {
            $highQualityRadio.Checked = $true
        }
        "LowQuality" {
            $lowQualityRadio.Checked = $true
        }
        "Disabled" {
            $disabledRadio.Checked = $true
        }
        "Custom" {
            # Don't check any radio button, show custom label
            $customQualityLabel.Visible = $true
        }
    }

    $statusLabel.Text = "Status: Registry values refreshed"
    & $enableApp -Enabled $true
}

# Create Refresh button
$refreshButton = New-Object System.Windows.Forms.Button
$refreshButton.Location = New-Object System.Drawing.Point(210, 605)
$refreshButton.Size = New-Object System.Drawing.Size(100, 30)
$refreshButton.Text = "Refresh"
$refreshButton.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$refreshButton.Add_Click({
    $refreshButton.Enabled = $false
    & $refreshAppState
    $refreshButton.Enabled = $true
})
$form.Controls.Add($refreshButton)
& $refreshAppState

# Create Close button
$closeButton = New-Object System.Windows.Forms.Button
$closeButton.Location = New-Object System.Drawing.Point(330, 605)
$closeButton.Size = New-Object System.Drawing.Size(100, 30)
$closeButton.Text = "Close"
$closeButton.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$closeButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.Controls.Add($closeButton)

$form.Controls.Add($statusLabel)

# Show the form
$form.Add_Shown({ $form.Activate() })
[void] $form.ShowDialog()
