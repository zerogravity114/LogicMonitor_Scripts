#Requires -Version 4
# Sets WMI, DCOM, SCManager, and Performance Manager permissions for the designated monitoring user.
# Script must be run locally.  Local execution of scripts must be enabled on the target system (Set-ExecutionPolicy RemoteSigned)

$DefaultMonitoringUser = "logicmonitor"


Function Set-CustomPermissions {
    Param(
    [Parameter(Mandatory=$true)]
    [string]$TargetUserName
    )
    $DCOMResultShort = $false
	$WMIResultShort = $false
	$SCManResultShort = $false
	$ProcessLocalGroups = $false
	$OperationResult = ""
				
	$SID = (New-Object System.Security.Principal.NTAccount($TargetUserName)).Translate([System.Security.Principal.SecurityIdentifier]).ToString()
				
	If (-not $SID)
	{
		$OperationResult += "User not found!!"
	}
	Else
	{
		$SDDL = "A;CI;CCDCWP;;;$SID"
		$DCOMSDDL = "A;;CCDCLCRP;;;$SID"
		$SCManSDDL = "A;;CCLCRPRC;;;$SID"
		$Reg = [WMIClass]"\\.\root\default:StdRegProv"
					
		#Patch DCOM Permisions
		$DCOM = $Reg.GetBinaryValue(2147483650, "software\microsoft\ole", "MachineLaunchRestriction").uValue
		$Converter = New-Object system.management.ManagementClass Win32_SecurityDescriptorHelper
		$OutDCOMSDDL = $Converter.BinarySDToSDDL($DCOM)
		if ($OutDCOMSDDL.SDDL -like "*$DCOMSDDL*")
		{
			$OperationResult += "DCOM: Already patched "
			$DCOMResultShort = $true
		}
		else
		{
			$NewDCOMSDDL = $OutDCOMSDDL.SDDL += "(" + $DCOMSDDL + ")"
			$DCOMbinarySD = $Converter.SDDLToBinarySD($NewDCOMSDDL)
			$ResultToNull = $Reg.SetBinaryValue(2147483650, "software\microsoft\ole", "MachineLaunchRestriction", $DCOMbinarySD.binarySD)
						
			#Check result
			$DCOM = $Reg.GetBinaryValue(2147483650, "software\microsoft\ole", "MachineLaunchRestriction").uValue
			$OutDCOMSDDL = $Converter.BinarySDToSDDL($DCOM)
			if ($OutDCOMSDDL.SDDL -like "*$DCOMSDDL*")
			{
				$OperationResult += "DCOM: Patched "
				$DCOMResultShort = $true
			}
			else
			{
				$OperationResult += "DCOM: Patching fail "
			}
		}
					
		#Patch WMI Permissions
		$Security = Get-WmiObject -ComputerName "." -Namespace root -Class __SystemSecurity
		$BinarySD = @($null)
		$ResultToNull = $Security.PsBase.InvokeMethod("GetSD", $BinarySD)
		$Outsddl = $Converter.BinarySDToSDDL($BinarySD[0])
					
		if ($Outsddl.SDDL -like "*$SDDL*")
		{
			$OperationResult += "WMI: Already patched "
			$WMIResultShort = $true
		}
		else
		{
			$NewSDDL = $Outsddl.SDDL += "(" + $SDDL + ")"
			$WMIbinarySD = $Converter.SDDLToBinarySD($NewSDDL)
			$WMIconvertedPermissions = ,$WMIbinarySD.BinarySD
			$ResultToNull = $Security.PsBase.InvokeMethod("SetSD", $WMIconvertedPermissions)
						
			#Check result
			$Security = Get-WmiObject -ComputerName "." -Namespace root -Class __SystemSecurity
			$BinarySD = @($null)
			$ResultToNull = $Security.PsBase.InvokeMethod("GetSD", $BinarySD)
			$Outsddl = $Converter.BinarySDToSDDL($BinarySD[0])
			if ($Outsddl.SDDL -like "*$SDDL*")
			{
				$OperationResult += "WMI: Patched."
				$WMIResultShort = $true
			}
			else
			{
				$OperationResult += "WMI: Patching fail."
			}
		}
					
		Restart-Service Winmgmt -force
					
		#Patch SCManager Permissions
		$SCManResult = [string](sc.exe sdshow scmanager)
		$OutSCMan = $SCManResult.Replace(" ", "")
					
		if ($OutSCMan -like "*$SCManSDDL*")
		{
			$OperationResult += "SC Manager: Already patched "
			$SCManResultShort = $true
		}
		else
		{
			$SCManPermissionMark = "D:(" + $SCManSDDL + ")"
			$NewSCMan = $OutSCMan.Replace("D:", $SCManPermissionMark)
			$outNull = (sc.exe sdset scmanager $NewSCMan)
						
			#Check Result
			$SCManResult = [string](sc.exe sdshow scmanager)
			$OutSCMan = $SCManResult.Replace(" ", "")
			if ($OutSCMan -like "*$SCManSDDL*")
			{
				$OperationResult += "SC Manager: Patched."
				$SCManResultShort = $true
			}
			else
			{
				$OperationResult += "SC Manager: Patching fail."
			}
		}
					
		#Add user to Performance Monitor Users
					
		$LocalGroupResult = [string](net localgroup "Performance Monitor Users")
		$TestUserName = $TargetUserName.ToLower()
					
		if ($LocalGroupResult.ToLower().IndexOf($TestUserName) -ne -1)
		{
			$OperationResult += "PerfMon Group: Already patched "
			$ProcessLocalGroups = $true
		}
		else
		{
			$outNull = [string](net localgroup "Performance Monitor Users" "$TargetUserName" /add)
			$LocalGroupResult = [string](net localgroup "Performance Monitor Users")
			$TestUserName = $TargetUserName.ToLower()
						
			if ($LocalGroupResult.ToLower().IndexOf($TestUserName) -ne -1)
			{
				$OperationResult += "PerfMon Group: Patched "
				$ProcessLocalGroups = $true
			}
			else
			{
				$OperationResult += "PerfMon Group: Patching fail "
			}
		}
					
	}
				
	if ($DCOMResultShort -and $WMIResultShort -and $SCManResultShort -and $ProcessLocalGroups)
	{
		$OperationResult = "OK"
	}
	else
	{
		$OperationResult = "failed"
	}
	return $OperationResult



}

$Result = Set-CustomPermissions -TargetUserName $DefaultMonitoringUser
if ($Result -like "OK"){
    New-EventLog -Source LogicMonitorScript -LogName System
    Write-EventLog -LogName System -EventId 4778 -Source LogicMonitorScript -EntryType SuccessAudit -Message "LogicMonitorScript succesfully created permissions for $($DefaultMonitoringUser)"
}
else {
    New-EventLog -Source LogicMonitorScript -LogName System
    Write-EventLog -LogName System -EventId 4778 -Source LogicMonitorScript -EntryType FailureAudit -Message "LogicMonitorScript failed to create permissions for $($DefaultMonitoringUser)"
}

Exit
