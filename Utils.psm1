New-Variable -Name ConsentPromptBehaviorAdmin_Name -Value "ConsentPromptBehaviorAdmin" 
New-Variable -Name PromptOnSecureDesktop_Name -Value "PromptOnSecureDesktop"  
New-Variable -Name Key -Value "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" 
 
function Get-RegValue($key, $value) {  
	(Get-ItemProperty $key $value).$value  
}  
 
function Get-UACLevel(){ 	
 	$ConsentPromptBehaviorAdmin_Value = Get-RegValue $Key $ConsentPromptBehaviorAdmin_Name 
 	$PromptOnSecureDesktop_Value = Get-RegValue $Key $PromptOnSecureDesktop_Name 
	If($ConsentPromptBehaviorAdmin_Value -Eq 0 -And $PromptOnSecureDesktop_Value -Eq 0){ 
		"Never notify" 
	} 
	ElseIf($ConsentPromptBehaviorAdmin_Value -Eq 5 -And $PromptOnSecureDesktop_Value -Eq 0){ 
		"NotIfy me only when apps try to make changes to my computer(do not dim my desktop)" 
	} 
	ElseIf($ConsentPromptBehaviorAdmin_Value -Eq 5 -And $PromptOnSecureDesktop_Value -Eq 1){ 
		"NotIfy me only when apps try to make changes to my computer(default)" 
	}
	ElseIf($ConsentPromptBehaviorAdmin_Value -Eq 2 -And $PromptOnSecureDesktop_Value -Eq 1){ 
		"Always notify" 
	} 
	Else{ 
		"Unknown" 
	} 
} 
     
function Set-UACLevel() { 
 Param([int]$Level= 2) 
 
	New-Variable -Name PromptOnSecureDesktop_Value 
	New-Variable -Name ConsentPromptBehaviorAdmin_Value 
 
	If($Level -In 0, 1, 2, 3) { 
		$ConsentPromptBehaviorAdmin_Value = 5 
		$PromptOnSecureDesktop_Value = 1 
		Switch ($Level)  
		{  
			0 { 
				$ConsentPromptBehaviorAdmin_Value = 0  
                        	$PromptOnSecureDesktop_Value = 0 
			}  
			1 { 
				$ConsentPromptBehaviorAdmin_Value = 5  
				$PromptOnSecureDesktop_Value = 0 
			}
			2 { 
				$ConsentPromptBehaviorAdmin_Value = 5 
				$PromptOnSecureDesktop_Value = 1 
			}
			3 { 
				$ConsentPromptBehaviorAdmin_Value = 2 
				$PromptOnSecureDesktop_Value = 1 
			}  
		} 
	Set-RegistryValue -Path $Key -Name $ConsentPromptBehaviorAdmin_Name -Value $ConsentPromptBehaviorAdmin_Value -Type 'Dword'
	Set-RegistryValue -Path $Key -Name $PromptOnSecureDesktop_Name -Value $PromptOnSecureDesktop_Value -Type 'Dword'
	} 
	Else{ 
		"No supported level" 
	}  
} 
 
function Test-RegistryValue {
param (
 [parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]$Path,
 [parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]$Value
)
	try {
		Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
		return $true
	}catch {
		return $false
	}
} 

function Set-RegistryValue{
param(
[parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]$Path,
 [parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]$Name,
 [parameter(Mandatory=$false)]
 [ValidateNotNullOrEmpty()]$Value,
 [parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]$Type

 )
	If ((Test-Path -Path $Path) -Eq $false) { 
		$entries = @($Path -split '\',-1,'SimpleMatch')
		$tmp = $entries[0]
		#echo $tmp
		Foreach ( $k in $entries[1..$entries.Count] ){
			$tmp = "$tmp\$k"

			if ((Test-Path -Path $tmp) -Eq $false) {
				New-Item -ItemType Directory -Path $tmp 
			}
		}
	}  
	If ($Type -Eq 'Dword') { 
		Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type 
	}
}

# Export-ModuleMember -Function Get-UACLevel 
Export-ModuleMember -Function Set-UACLevel
Export-ModuleMember -Function Set-RegistryValue
