# CloneCertificate


This script was designed to extract and clone the certificate chain from digitaly signed files, and to sign your file 
using the cloned certificate.  
The idea of the script was taken from the [post](https://posts.specterops.io/code-signing-certificate-cloning-attacks-and-defenses-6f98657fc6ec)
 of great :)  Matt Graeber from amaizing SpectOps Team. 


Clone Certificate:   
.\CloneCertificate -OriginalFile c:\temp\original.exe -FileToSign c:\temp\file.exe

Clone and install:  
.\CloneCertificate -OriginalFile c:\temp\original.exe -FileToSign c:\temp\file.exe -InstallCertificate
    
