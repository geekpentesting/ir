<#
.SYNOPSIS 
This scriptis for testing purposes only. Malicious use of this script is prohibitted. 
Encrypt or Decrypt a single file.

.DESCRIPTION
Encrypts or Decrypts files using AES.

.NOTES
Author of FileCryptorator script @cyb3rw01f
#>

$logo = @"
	=================================================================
				   _                         ___  _  __ 
			 ___ _   _| |__   ___ _ ____      __/ _ \/ |/ _|
			/ __| | | | '_ \ / _ \ '__\ \ /\ / / | | | | |_ 
		       | (__| |_| | |_) |  __/ |   \ V  V /| |_| | |  _|
			\___|\__, |_.__/ \___|_|    \_/\_/  \___/|_|_|  
			     |___/                                      
		
	==================================================================
		 *     *    *     /\__/\  *    ---    *
                   *            /      \    /     \    
                        *   *  |  -  -  |  |       |*   
                 *   __________| \     /|  |       |    
                   /              \ T / |   \     /    
                 /                      |  *  ---
                |  ||     |    |       /             *
                |  ||    /______\     / |*     *
                |  | \  |  /     \   /  |
                 \/   | |\ \      | | \ \
                      | | \ \     | |  \ \
                      | |  \ \    | |   \ \
                      '''   '''   '''    ''
		             @cyberw01f								  
"@

$label = @"  
                
                       Responsible use only permited
"@

Function Export-EncryptedFile
{
    param(
        [string]$InFilePath,
        [string]$OutFilePath,
        [string]$Password
    )
    begin
    {
        Function Get-SHA256Hash
        {
            param(
                [string]$inputString
            )
            process
            {
                [System.Security.Cryptography.SHA256]$SHA256 = [System.Security.Cryptography.SHA256]::Create()
                return $SHA256.ComputeHash([System.Text.ASCIIEncoding]::UTF8.GetBytes($inputString))
            }
        }
    }
    process
    {
        [System.Security.Cryptography.AesCryptoServiceProvider]$Aes =  [System.Security.Cryptography.AesCryptoServiceProvider]::new()
        $Aes.BlockSize = 128
        $Aes.KeySize = 256
        $Aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $Aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $Aes.GenerateIV()
        [byte[]]$IV = $Aes.IV
        [byte[]]$Key = Get-SHA256Hash -inputString $Password
        [System.IO.FileStream]$FileStreamOut = [System.IO.FileStream]::new($OutFilePath,[System.IO.FileMode]::Create)
        [System.Security.Cryptography.ICryptoTransform]$ICryptoTransform = $Aes.CreateEncryptor($Key,$IV)
        [System.Security.Cryptography.CryptoStream]$CryptoStream = [System.Security.Cryptography.CryptoStream]::new($FileStreamOut, $ICryptoTransform, [System.Security.Cryptography.CryptoStreamMode]::Write)
        [System.IO.FileStream]$FileStreamIn = [System.IO.FileStream]::new($InFilePath,[System.IO.FileMode]::Open)
 
        $FileStreamOut.Write($IV,0,$IV.Count)
        $DataAvailable = $true
        [int]$Data
 
        While ($DataAvailable)
        {
            $Data = $FileStreamIn.ReadByte()
            if($Data -ne -1)
            {
                $CryptoStream.WriteByte([byte]$Data)
            }
            else
            {
                $DataAvailable = $false
            }
        }
 
        $FileStreamIn.Dispose()
        $CryptoStream.Dispose()
        $FileStreamOut.Dispose()
 
    }


}
 
 

function Encrypter
{
        $paswd = "1234"
        #Get-File
        New-Item "$($ENV:UserProfile)\Desktop\Confidential.txt"
        Set-Content "$($ENV:UserProfile)\Desktop\Confidential.txt" 'Secure Password for SSH is $ecret!k#^7*(&@#$'
        $inFileName =  "$($ENV:UserProfile)\Desktop\Confidential.txt"
        $outFileName = "$($ENV:UserProfile)\Desktop\$file.encrypted"
        Export-EncryptedFile -InFilePath $inFileName -OutFilePath $outFileName -Password $paswd
        Write-Host -f Green "Your encrypted file is located at"
        Write-Host -f Yellow "$($ENV:UserProfile)\Desktop\$file.encrypted"
        exit
    }



Function Set-WallPaper {
 
param (
    [parameter(Mandatory=$True)]
    # Provide path to image
    [string]$Image,
    # Provide wallpaper style that you would like applied
    [parameter(Mandatory=$False)]
    [ValidateSet('Fill', 'Fit', 'Stretch', 'Tile', 'Center', 'Span')]
    [string]$Style
)

wget https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2020/10/22094330/sl_maze_ransomware_01.png -outfile "$($ENV:UserProfile)\Desktop\ran.png"
 
$WallpaperStyle = Switch ($Style) {
  
    "Fill" {"10"}
    "Fit" {"6"}
    "Stretch" {"2"}
    "Tile" {"0"}
    "Center" {"0"}
    "Span" {"22"}
  
}
 
If($Style -eq "Tile") {
 
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name WallpaperStyle -PropertyType String -Value $WallpaperStyle -Force
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name TileWallpaper -PropertyType String -Value 1 -Force
 
}
Else {
 
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name WallpaperStyle -PropertyType String -Value $WallpaperStyle -Force
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name TileWallpaper -PropertyType String -Value 0 -Force
 
}
 
Add-Type -TypeDefinition @" 
using System; 
using System.Runtime.InteropServices;
  
public class Params
{ 
    [DllImport("User32.dll",CharSet=CharSet.Unicode)] 
    public static extern int SystemParametersInfo (Int32 uAction, 
                                                   Int32 uParam, 
                                                   String lpvParam, 
                                                   Int32 fuWinIni);
}
"@ 
  
    $SPI_SETDESKWALLPAPER = 0x0014
    $UpdateIniFile = 0x01
    $SendChangeEvent = 0x02
  
    $fWinIni = $UpdateIniFile -bor $SendChangeEvent
  
    $ret = [Params]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $Image, $fWinIni)
}
 


Write-Host -f Magenta $logo
Write-Host
Write-Host -f Green $label 
Encrypter

Set-WallPaper -Image "$($ENV:UserProfile)\Desktop\ran.png" -Style Fit