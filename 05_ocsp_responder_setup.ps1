
# PKI Lab - OCSP Responder Setup Script (flocsp or nyocsp1)
# Run on each OCSP responder server

# 1. Install Online Responder role
Install-WindowsFeature ADCS-Online-Cert -IncludeManagementTools

# 2. Configure revocation configurations for both Issuing CAs (manual GUI step)
Write-Host "Configure revocation configurations for PKILab Issuing CA - FL and PKILab Issuing CA - NY via Online Responder Management console."

# 3. Enroll OCSP Response Signing certificates (autoenroll or manual)
Write-Host "Enroll OCSP Response Signing certificates for each revocation configuration."

# 4. Verify OCSP responder status
Write-Host "Verify OCSP responder status is Online and serving requests."

# 5. Verification
Write-Host "Test OCSP responder by running certutil -url <end-entity-cert> and selecting OCSP."
