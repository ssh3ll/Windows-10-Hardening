# Windows-10-hardening

### Description
The goal of this project is to improve both privacy and security that are provided by default in your Windows 10 operating system, either Pro or Home edition.

The Powershell script is intended to harden your OS. It does so by turning on/off some specific features known to have led to several attacks and security vulnerabilities in the paste, or that might affect the privacy of the system users. 
It also uninstalls and disables known services and default applications which are not needed by the majority of the users. 


Thus, it attempts to remove/disable every unneeded application, protocol, and more in general software that stand on your operating system just to increase the attack surface. Among the applications the script removes you can find the Bing and XBox applications that are installed by default and many others. 

Some of the protocols disabled by the script are mentioned below:
- NetBios
- RDP
- Unsecure SSL and TLS versions
- IPv6

**Note:** The script must be executed with Administrator privileges in order to complete successfully and it also requires a computer restart to apply all the changes. 

<br />


### Recommendation

In order to prevent any issue that this script may cause to your system, please take a backup of your registry hives before you run it, so that you can restore all the registry keys to their previous values. 
The script uninstall only those applications that are installed by default on every Windows OS and which are not used by the majority of the users. However, you might be among those restricted range of users that need (for instance) the '3D Viewer' application, in that situation you will need to reinstall the software. 


Even though the script has been fully tested with no issue on the latest version of Windows 10 (Home and Pro edition) I *do NOT* assume any responsibility regarding any issue it may cause to your systems. The source code is publicly accessible and therefore you're allowed to inspect its statements or just take a backup as already mentioned before.



### How to Run

Open a CMD prompt and run the following command from the directory that contains the target script:

      powershell -exec bypass ".\os_hardening.ps1"

In case you don't use Windows Defender as your anti-malware solution, run the script as shown below:

    powershell -exec bypass ".\os_hardening.ps1 -NoAV"

### Contribution

If you have any idea, advice, or improvement feel free to open an issue or contact me directly. 

Pull requests are welcome!!
