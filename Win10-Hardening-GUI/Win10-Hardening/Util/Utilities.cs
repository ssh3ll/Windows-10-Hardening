using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Management.Automation;
using System.Security.Principal;
using System.Windows;
using System.Windows.Controls;

namespace Win10Hardening.Util
{
    class Utilities
    {
        static private string SetRegistryValFunction = @"function Set-RegistryValue{
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
			$tmp = -join($tmp, '\', $k)

            if ((Test-Path -Path $tmp) -Eq $false) {
                New-Item -ItemType Directory -Path $tmp
            }
        }
    }
    If($Type -Eq 'Dword')
    {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
    }
}";
        static private string SetUacFunction = @"function Set-UACLevel() { 
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
}";

        static public bool IsAdministrator()
        {
            // Returns true the process is running with Administrator privileges, otherwise it returns false.
            return (new WindowsPrincipal(WindowsIdentity.GetCurrent()))
                      .IsInRole(WindowsBuiltInRole.Administrator);
        }

        static public List<string> GetApplications()
        {
            List<string> res = new List<string>();

            using (PowerShell pw = PowerShell.Create())
            {
                pw.AddCommand("Get-AppxPackage");

                foreach (PSObject o in pw.Invoke())
                    if (o != null)
                        if (o.Properties["Nonremovable"].Value.ToString().Equals("False"))      // if it's removables
                            res.Add($"{o.Properties["Name"].Value.ToString()}---{o.Properties["Publisher"].Value.ToString()}");
            }

            res.Sort();
            return res;
        }

        static public List<string> GetRunningServices()
        {
            List<string> res = new List<string>();

            using (PowerShell pw = PowerShell.Create())
            {
                pw.AddCommand("Get-Service");

                Collection<PSObject> psOut = pw.Invoke();
                foreach (PSObject o in psOut)
                    if (o != null)
                        if (o.Properties["Status"].Value.ToString().Equals("Running"))
                            res.Add(o.Properties["Name"].Value.ToString());
            }

            res.Sort();
            return res;
        }

        static public CheckBox BuildSelectChkBox(string name, string content, Thickness thickness, bool isChecked = false, int width=100)
        { 
            if (width != 100)
                return new CheckBox
                {
                    Name = name,
                    IsChecked = isChecked,
                    Content = content, 
                    Margin = thickness,
                    Width = width
                };
            else
                return new CheckBox
                {
                    Name = name,
                    IsChecked = isChecked,
                    Content = content,
                    Margin = thickness
                };
        }

        static public CheckBox ChckBox(string name, string content, Thickness thickness)
        {
            return new CheckBox
            {
                Name = name,
                IsChecked = false,
                Content = content,
                Width = 240,
                Height = 30,
                Visibility = Visibility.Visible,
                HorizontalAlignment = HorizontalAlignment.Left,
                VerticalAlignment = VerticalAlignment.Top,
                Margin = thickness
            };
        }

        static public void PerformRegistryBackup(string folder)
        {
            string[] hives = new string[] { "HKLM", "HKCU", "HKCR" };
            DirectoryInfo di = new DirectoryInfo(folder);

            // Delete any previously created registry backup file
            foreach (FileInfo file in di.EnumerateFiles())
            {
                if (file.Name.EndsWith(".reg"))
                    file.Delete();
            }

            // Performs the registry hives backup
            foreach (var h in hives)
            {
                Process process = new System.Diagnostics.Process();
                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.WindowStyle = ProcessWindowStyle.Hidden;
                startInfo.FileName = "reg.exe";
                startInfo.Arguments = "export " + h + " " + folder + "\\" + h.ToLower() + ".reg";
                process.StartInfo = startInfo;
                process.Start();

                process.WaitForExit();
            }
        }
        
        static public void UninstallApps(List<string> apps_selected)
        {
            // Uninstall selected Applications
            if (apps_selected.Count != 0)
            {
                PowerShell ps = PowerShell.Create();
                foreach (string a in apps_selected)
                {
                    string script = string.Format("Get-AppxPackage {0} -AllUsers | Remove-AppxPackage -ErrorAction 'SilentlyContinue'", a);
                    ps.AddScript(script);
                }

                ps.Invoke();
            }
        }

        static public void DisableServices(List<string> services_selected)
        {
            // Disable selectes Services
            if (services_selected.Count != 0)
            {
                PowerShell ps = PowerShell.Create();
                foreach (var s in services_selected)
                {
                    string script1 = string.Format("Set-Service -Name {0} -StartupType 'Disabled'", s);
                    string script2 = string.Format("Stop-Service -Name {0} -Force", s);

                    ps.AddScript(script1);
                    ps.AddScript(script2);
                }

                ps.Invoke();
            }
        }

        static public void HardenOffice(List<String> office_selected)
        {
            PowerShell ps = PowerShell.Create();
            ps.AddScript(SetRegistryValFunction);
            ps.Invoke();

            foreach (var str in office_selected)
            {
                switch (str)
                {
                    case "Disable Macros":
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\access\\security\" -Name vbawarnings -Type Dword -Value 4");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\excel\\security\" -Name vbawarnings -Value 4 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\excel\\security\" -Name blockcontentexecutionfrominternet -Value 1 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\excel\\security\" -Name excelbypassencryptedmacroscan -Value 0 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\ms project\\security\" -Name vbawarnings -Value 4 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\ms project\\security\" -Name level -Value 4 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\outlook\\security\" -Name level -Value 4 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\powerpoint\\security\" -Name vbawarnings -Value 4 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\powerpoint\\security\" -Name blockcontentexecutionfrominternet -Value 1 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\publisher\\security\" -Name vbawarnings -Value 4 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\visio\\security\" -Name vbawarnings -Value 4 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\visio\\security\" -Name blockcontentexecutionfrominternet -Value 1 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\word\\security\" -Name vbawarnings -Value 4 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\word\\security\" -Name blockcontentexecutionfrominternet -Value 1 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\word\\security\" -Name wordbypassencryptedmacroscan -Value 0 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\common\\security\" -Name automationsecurity -Value 3 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\outlook\\options\\mail\" -Name blockextcontent -Value 1 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\outlook\\options\\mail\" -Name junkmailenablelinks -Value 0 -Type Dword");
                        break;
                    case "Disable DDE":
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Microsoft\\office\\16.0\\Excel\\Security\" -Name WorkbookLinkWarnings -Value 2 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Microsoft\\Office\\16.0\\Word\\Options\\WordMail\" -Name DontUpdateLinks -Value 1 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Microsoft\\Office\\16.0\\Word\\Options\" -Name DontUpdateLinks -Value 1 -Type Dword");
                        break;
                    case "Enable Automatic Updates":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\office\\16.0\\common\\officeupdate\" -Name EnableAutomaticUpdates -Type Dword -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\office\\16.0\\common\\officeupdate\" -Name HideEnableDisableUpdates -Type Dword -Value 1");
                        break;
                    case "Disable Feedback":
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\common\\feedback\" -Name enabled -Type Dword -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\common\\feedback\" -Name includescreenshot -Type Dword -Value 0");
                        break;
                    case "Disable Data Collection & Telemetry":
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\common\\general\" -Name notrack -Type Dword -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\common\\general\" -Name optindisable -Type Dword -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\common\\general\" -Name shownfirstrunoptin -Type Dword -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\common\\ptwatson\" -Name ptwoptin -Type Dword -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\firstrun\" -Name bootedrtm -Type Dword -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\firstrun\" -Name disablemovie -Type Dword -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\osm\" -Name enablefileobfuscation -Type Dword -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\osm\" -Name enablelogging -Type Dword -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\osm\" -Name enableupload -Type Dword -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\osm\\preventedapplications\" -Name accesssolution -Type Dword -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\osm\\preventedapplications\" -Name olksolution -Type Dword -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\osm\\preventedapplications\" -Name onenotesolution -Type Dword -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\osm\\preventedapplications\" -Name pptsolution -Type Dword -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\osm\\preventedapplications\" -Name projectsolution -Type Dword -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\osm\\preventedapplications\" -Name publishersolution -Type Dword -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\osm\\preventedapplications\" -Name visiosolution -Type Dword -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\osm\\preventedapplications\" -Name wdsolution -Type Dword -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\osm\\preventedapplications\" -Name xlsolution -Type Dword -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\osm\\preventedsolutiontypes\" -Name agave -Type Dword -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\osm\\preventedsolutiontypes\" -Name appaddins -Type Dword -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\osm\\preventedsolutiontypes\" -Name comaddins -Type Dword -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\osm\\preventedsolutiontypes\" -Name documentfiles -Type Dword -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\osm\\preventedsolutiontypes\" -Name templatefiles -Type Dword -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\Office\\16.0\\Outlook\\Options\\Mail\" -Name EnableLogging -Type Dword -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\Office\\16.0\\Word\\Options\" -Name EnableLogging -Type Dword -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\Office\\Common\\ClientTelemetry\" -Name DisableTelemetry -Type Dword -Value 1");

                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\common\\services\\fax\" -Name nofax -Type Dword -Value 1");
                        break;
                    case "Deny Internet for Office":
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\office\\16.0\\common\\internet\" -Name useonlinecontent -Type Dword -Value 0");
                        break;
                    case "Disable Online Repair":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\office\\16.0\\common\\officeupdate\" -Name onlinerepair -Type Dword -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\office\\16.0\\common\\officeupdate\" -Name fallbacktocdn -Type Dword -Value 0");
                        break;
                }
            }
            ps.Invoke();
        }

        static public void HardenIE(List<String> ie_selected)
        {
            PowerShell ps = PowerShell.Create();
            ps.AddScript(SetRegistryValFunction);
            ps.Invoke();

            foreach (var str in ie_selected)
            {
                switch (str)
                {
                    // IE
                    case "Disable Location":
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\Internet Explorer\\Geolocation\" -Name PolicyDisableGeolocation -Type Dword -Value 1");
                        break;
                    case "Enable Phishing Filter":
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\Internet Explorer\\PhishingFilter\" -Name EnabledV9 -Type Dword -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\PhishingFilter\" -Name EnabledV9 -Type Dword -Value 1");
                        break;
                    case "Disable inPrivate logging":
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\Internet Explorer\\Safety\\PrivacIE\" -Name DisableLogging -Type Dword -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Safety\\PrivacIE\" -Name DisableLogging -Type Dword -Value 1");
                        break;
                    case "Disable CEIP":
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\Internet Explorer\\SQM\" -Name DisableCustomerImprovementProgram -Type Dword -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\SQM\" -Name DisableCustomerImprovementProgram -Type Dword -Value 0");
                        break;
                    case "Disable Suggestions":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\" -Name AllowServicePoweredQSA -Type Dword -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\DomainSuggestion\" -Name Enabled -Type Dword -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\SearchScopes\" -Name TopResult -Type Dword -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Suggested Sites\" -Name Enabled -Type Dword -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Main\" -Name AutoSearch -Type Dword -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Main\\WindowsSearch\" -Name EnabledScopes -Type Dword -Value 0");
                        break;
                    case "Disable Continuous Browsing":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\ContinuousBrowsing\" -Name Enabled -Type Dword -Value 0");
                        break;
                    case "Disable SSLv3 Fallback":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" -Name CallLegacyWCMPolicies -Type Dword -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" -Name EnableSSL3Fallback -Type Dword -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" -Name PreventIgnoreCertErrors -Type Dword -Value 1");
                        break;
                    case "Disable Prefetching":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\PrefetchPrerender\" -Name Enabled -Type Dword -Value 0");
                        break;
                    case "Always send DNT Header":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Main\" -Name DoNotTrack -Type Dword -Value 1");
                        break;
                    case "Disable Crash Detection":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Restrictions\" -Name NoCrashDetection -Type Dword -Value 1");
                        break;
                    case "Clear History on Exit":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Privacy\" -Name ClearBrowsingHistoryOnExit -Type Dword -Value 1");
                        break;
                    case "Force HTTP/2":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" -Name EnableHTTP2 -Type Dword -Value 1");
                        break;
                }
            }
            ps.Invoke();
        }

        static public void HardenEdge(List<String> edge_selected)
        {
            PowerShell ps = PowerShell.Create();
            ps.AddScript(SetRegistryValFunction);
            ps.Invoke();

            foreach (var str in edge_selected)
            {
                switch (str)
                {
                    // Edge
                    case "Disable Flash Player":
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\MicrosoftEdge\\Addons\" -Name FlashPlayerEnabled -Value 0 -Type Dword");
                        break;
                    case "Always send the DNT Header":
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\MicrosoftEdge\\Main\" -Name DoNotTrack -Value 1 -Type Dword");
                        break;
                    case "Disable Third-party Cookies":
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\MicrosoftEdge\\Main\" -Name Cookies -Value 1 -Type Dword");
                        break;
                    case "Prevent Data Collection":
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\MicrosoftEdge\\Main\" -Name PreventLiveTileDataCollection -Value 1 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\Windows\\EdgeUI\" -Name DisableMFUTracking -Value 1 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\Windows\\EdgeUI\" -Name DisableRecentApps -Value 1 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\Windows\\EdgeUI\" -Name TurnOffBackstack -Value 1 -Type Dword");
                        break;
                    case "Disable Help Prompt":
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\Windows\\EdgeUI\" -Name DisableHelpSticker -Value 1 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EdgeUI\" -Name DisableHelpSticker -Value 1 -Type Dword");
                        break;
                    case "Enable Phishing Filter":
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter\" -Name EnabledV9 -Value 1 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter\" -Name EnabledV9 -Value 1 -Type Dword");
                        break;
                    case "Clear History on Exit":
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\MicrosoftEdge\\Privacy\" -Name ClearBrowsingHistoryOnExit -Value 1 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Privacy\" -Name ClearBrowsingHistoryOnExit -Value 1 -Type Dword");
                        break;
                    case "Disable Suggestions":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\SearchScopes\" -Name ShowSearchSuggestionsGlobal -Value 0 -Type Dword");
                        break;
                }
            }
            ps.Invoke();
        }

        static public void HardenNet(List<String> netword_selected)
        {
            PowerShell ps = PowerShell.Create();
            ps.AddScript(SetRegistryValFunction);
            ps.Invoke();

            foreach (var str in netword_selected)
            {
                switch (str)
                {
                    case "Flush Caches":
                        ps.AddScript("Ipconfig /flushdns");
                        ps.AddScript("netsh interface ipv4 delete arpcache");
                        ps.AddScript("netsh interface ipv4 delete destinationcache");
                        ps.AddScript("netsh interface ipv4 delete neighbors");
                        ps.AddScript("Set-Variable -Name 'Adapter' -Value (Get-NetAdapter -Name 'Ethernet*' -Physical | Select-Object -ExpandProperty 'Name')");
                        ps.AddScript("netsh interface ipv4 delete winsservers $Adapter all");
                        ps.AddScript("Remove-Item -Path \"$env:SystemRoot\\System32\\drivers\\etc\\hosts\" -force");
                        ps.AddScript("New-Item -Path \"$env:SystemRoot\\System32\\drivers\\etc\" -Name hosts -ItemType file -Value '# Flushed.' -Force");
                        break;
                    case "Disable Unneeded Net Interfaces":
                        ps.AddScript("Disable-NetAdapterBinding -Name '*' -ComponentID 'ms_lldp'");
                        ps.AddScript("Disable-NetAdapterBinding -Name '*' -ComponentID 'ms_implat'");
                        ps.AddScript("Disable-NetAdapterBinding -Name '*' -ComponentID 'ms_lltdio'");
                        ps.AddScript("Disable-NetAdapterBinding -Name '*' -ComponentID 'ms_server'");
                        ps.AddScript("Disable-NetAdapterBinding -Name '*' -ComponentID 'ms_rspndr'");
                        ps.AddScript("Disable-NetAdapterBinding -Name '*' -ComponentID 'ms_msclient'");
                        ps.AddScript("Disable-NetAdapterBinding -Name '*' -ComponentID 'ms_pacer'");
                        break;
                    case "Disable Unsafe Net Protocols":
                        ps.AddScript("Set-Variable -Name Path -Value \"Registry::HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\"");
                        ps.AddScript("$Protocols = @('DTLS 1.0', 'PCT 1.0', 'SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1')");

                        ps.AddScript(@"Foreach ($Protocol in $Protocols) {
if(!(Test-Path -join($Path, '\', $Protocol))){
New-Item -Path $Path -Name $Protocol -Type 'Directory'
}
Set-Variable -Name 'key' -Value $Path\$Protocol
Set-RegistryValue -Path $key -Name 'Client' -Type 'Directory'
Set-RegistryValue -Path $key -Name 'Server' -Type 'Directory'

Set-RegistryValue -Path $key\Client -Name DisabledByDefault -Value 1 -Type Dword
Set-RegistryValue -Path $key\Client -Name Enabled -Value 0 -Type Dword
Set-RegistryValue -Path $key\Server -Name DisabledByDefault -Value 1 -Type Dword
Set-RegistryValue -Path $key\Server -Name Enabled -Value 0 -Type Dword
" +
"}");
                        break;
                    case "Disable IPv6":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\" -Name DisabledComponents -Value '0xFF' -Type Dword");
                        ps.AddScript("Disable-NetAdapterBinding -Name '*' -ComponentID 'ms_tcpip6'");
                        break;
                    case "Disable SMB Server":
                        ps.AddScript("Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force");
                        ps.AddScript("Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol");
                        ps.AddScript("Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:SYSTEM\\CurrentControlSet\\services\\NetBT\\Parameters\" -Name SMBDeviceEnabled -Value 0 -Type Dword");
                        break;
                    case "Disable Sharing Mapped Drives":
                        ps.AddScript("Remove-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" -Name EnableLinkedConnections -ErrorAction SilentlyContinue");
                        break;
                    case "Disable Admin Shares":
                        ps.AddScript("Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" -Name AutoShareWks -Type DWord -Value 0");
                        break;
                    case "Disable NetBios":
                        ps.AddScript("$key = \"HKLM:SYSTEM\\CurrentControlSet\\services\\NetBT\\Parameters\\Interfaces\"");
                        ps.AddScript("Get-ChildItem $key | ForEach-Object { Set-ItemProperty -Path \"$key\\$($_.pschildname)\" -Name NetBiosOptions - Value 2 }");
                        break;
                    case "Disable LLMNR":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\" -Name EnableMulticast -Type DWord -Value 0");
                        break;
                    case "Disable RDP":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\" -Name fDenyTSConnections -Type Dword -Value 1");
                        break;
                    case "Disable Remote Assistance":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\" -Name fAllowToGetHelp -Type Dword -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\" -Name fAllowUnsolicited -Type Dword -Value 0");
                        break;
                    case "Mandatory Encrypted Tickets":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\" -Name CreateEncryptedOnlyTickets -Type Dword -Value 1");
                        break;
                    case "Disable Remote Desktop Sharing":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Conferencing\" -Name NoRDS -Type Dword -Value 1");
                        break;
                    case "Disable Password Saving":
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\" -Name DisablePasswordSaving -Type Dword -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\" -Name DisablePasswordSaving -Type Dword -Value 1");
                        break;
                    case "Do not allow Remote Shell":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\WinRS\" -Name AllowRemoteShellAccess -Type Dword -Value 0");
                        break;
                }
            }
            ps.Invoke();
        }

        static public void HardenMisc(List<String> misc_selected, string uac_level)
        {
            PowerShell ps = PowerShell.Create();
            ps.AddScript(SetRegistryValFunction);
            ps.Invoke();
            ps.AddScript("New-Variable -Name ConsentPromptBehaviorAdmin_Name -Value ConsentPromptBehaviorAdmin");
            ps.AddScript("New-Variable -Name PromptOnSecureDesktop_Name -Value PromptOnSecureDesktop");
            ps.AddScript("New-Variable -Name Key -Value \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\"");
            ps.Invoke();
            ps.AddScript(SetUacFunction);
            ps.Invoke();

            int uac_int_lvl = -1;

            if (uac_level == "Low")
            {
                uac_int_lvl = 1;
            }
            else if (uac_level == "Medium")
            {
                uac_int_lvl = 2;
            }
            else if (uac_level == "High")
            {
                uac_int_lvl = 3;
            }

            ps.AddScript("Set-UACLevel " + uac_int_lvl.ToString());

            foreach (var str in misc_selected)
            {
                switch (str)
                {
                    case "Disable AutoPlay & AutoRun":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" -Name NoAutorun -Value 1 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" -Name NoDriveTypeAutoRun -Value 255 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers\" -Name DisableAutoplay -Value 1 -Type Dword");
                        break;
                    case "Disable Find MyDevice":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\FindMyDevice\" -Name AllowFindMyDevice -Value 0 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Microsoft\\Settings\\FindMyDevice\" -Name LocationSyncEnabled -Value 0 -Type Dword");
                        break;
                    case "Disable Win Insider Program":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PreviewBuilds\" -Name AllowBuildPreview -Value 0 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PreviewBuilds\" -Name EnableConfigFlighting -Value 0 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\" -Name ManagePreviewBuilds -Value 1 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\" -Name ManagePreviewBuildsPolicyValue -Value 0 -Type Dword");
                        break;
                    case "Disable WiFi Sense":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\Software\\Microsoft\\PolicyManager\\default\\WiFi\\AllowWiFiHotSpotReporting\" -Name Value -Type DWord -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\Software\\Microsoft\\PolicyManager\\default\\WiFi\\AllowAutoConnectToWiFiSenseHotspots\" -Name Value -Type DWord -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\config\" -Name AutoConnectAllowedOEM -Type Dword -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\config\" -Name WiFISenseAllowed -Type Dword -Value 0");
                        break;
                    case "Disable Telemetry":
                        ps.AddScript("Set-RegistryValue -Path \"Registry::HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection\" -Name AllowTelemetry -Type Dword -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"Registry::HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection\" -Name AllowTelemetry -Type Dword -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"Registry::HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" -Name AllowTelemetry -Type Dword -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"Registry::HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PreviewBuilds\" -Name AllowBuildPreview -Type Dword -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"Registry::HKCU\\Software\\Policies\\Microsoft\\Windows\\DataCollection\" -Name AllowTelemetry -Type Dword -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"Registry::HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat\" -Name AITEnable -Type Dword -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"Registry::HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" -Name LimitEnhancedDiagnosticDataWindowsAnalytics -Type Dword -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"Registry::HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" -Name DoNotShowFeedbackNotifications -Type Dword -Value 1");

                        ps.AddScript("Disable-ScheduledTask -TaskName \"Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser\" | Out-Null");
                        ps.AddScript("Disable-ScheduledTask -TaskName \"Microsoft\\Windows\\Application Experience\\ProgramDataUpdater\" | Out-Null");
                        ps.AddScript("Disable-ScheduledTask -TaskName \"Microsoft\\Windows\\Autochk\\Proxy\" | Out-Null");
                        ps.AddScript("Disable-ScheduledTask -TaskName \"Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator\" | Out-Null");
                        ps.AddScript("Disable-ScheduledTask -TaskName \"Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip\" | Out-Null");
                        ps.AddScript("Disable-ScheduledTask -TaskName \"Microsoft\\Windows\\DiskDiagnostic\\Microsoft - Windows - DiskDiagnosticDataCollector\" | Out-Null");
                        break;
                    case "Enable SmartScreen":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\" -Name EnableSmartScreen -Type DWord -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter\" -Name EnabledV9 -Type DWord -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost\" -Name EnableWebContentEvaluation -Type Dword -Value 1");
                        break;
                    case "Disable WebSearch":
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search\" -Name BingSearchEnabled -Type DWord -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search\" -Name CortanaConsent -Type DWord -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search\" -Name DisableWebSearch -Type DWord -Value 1");
                        break;
                    case "Disable Background Apps":
                        Console.WriteLine(string.Format("Case '{0}'", str));
                        break;
                    case "Disable Feedback":
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\SOFTWARE\\Microsoft\\Siuf\\Rules\" -Name NumberOfSIUFInPeriod -Type DWord -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" -Name DoNotShowFeedbackNotifications -Type DWord -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\Assistance\\Client\\1.0\" -Name NoExplicitFeedback -Type DWord -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\Assistance\\Client\\1.0\" -Name NoImplicitFeedback -Type DWord -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Software\\Policies\\Microsoft\\Assistance\\Client\\1.0\" -Name NoOnlineAssist -Type DWord -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Assistance\\Client\\1.0\" -Name NoActiveHelp -Type DWord -Value 1");

                        ps.AddScript("Disable-ScheduledTask -TaskName \"Microsoft\\Windows\\Feedback\\Siuf\\DmClient\" -ErrorAction SilentlyContinue | Out-Null");
                        ps.AddScript("Disable-ScheduledTask -TaskName \"Microsoft\\Windows\\Feedback\\Siuf\\DmClientOnScenarioDownload\" -ErrorAction SilentlyContinue | Out-Null");
                        break;
                    case "Disable Advertising ID":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo\" -Name Enabled -Type DWord -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo\" -Name DisabledByGroupPolicy -Type DWord -Value 1");
                        break;
                    case "Disable Sticky Keys":
                        ps.AddScript("Set-RegistryValue -Path \"HKCU:\\Control Panel\\Accessibility\\StickyKeys\" -Name Flags -Value 506 -Type Dword");
                        break;
                    case "Enable Real-Time Monitoring":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" -Name DisableIOAVProtection -Type Dword -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" -Name DisableBehaviorMonitoring -Type Dword -Value 1");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" -Name DisableRealtimeMonitoring -Type Dword -Value 0");
                        break;
                    case "Disable Automatic Sample Submission":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\SpyNet\" -Name SpyNetReporting -Type Dword -Value 0");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\SpyNet\" -Name SubmitSamplesConsent -Type Dword -Value 2");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Reporting\" -Name DisableGenericRePorts -Type Dword -Value 1");
                        break;
                    case "Check Signatures before any Scan":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan\" -Name CheckForSignaturesBeforeRunningScan -Type Dword -Value 1");
                        break;
                    case "Disable Active Desktop":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" -Name ForceActiveDesktopOn -Value 0 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" -Name NoActiveDesktop -Value 1 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" -Name NoActiveDesktopChanges -Value 1 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop\" -Name NoAddingComponents -Value 1 -Type Dword");
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop\" -Name NoComponents -Value 1 -Type Dword");
                        break;
                    case "Disable Picture Password":
                        ps.AddScript("Set-RegistryValue -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\" -Name BlockDomainPicturePassword -Value 1 -Type Dword");
                        break;
                    case "Enhance Face Spoofing Protection":
                        ps.AddScript("Set-RegistryValue -Name \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Biometrics\\FacialFeatures\" -Name EnhancedAntiSpoofing -Value 1 -Type Dword");
                        break;
                }
            }
            ps.Invoke();
        }
    }
}
