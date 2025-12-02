# Certificate Templates
## Duplicate Webserver Template for /Certsrv

### Step 1: Open Certificate Templates Console
```text
Log in to your Subordinate CA server (e.g., subca1.lab.local) with an account that has Enterprise Admin or CA Administrator privileges.
Open Server Manager.
From the Tools menu, select Certificate Authority.
In the Certificate Authority console, expand your CA (e.g., Lab Issuing CA 1).
Select Certificate Templates.
Right click and select "Manage"
```   

### Step 2: Duplicate the Web Server Template
```text   
In the Certificate Templates pane, right-click on the Web Server template.   
Select Duplicate Template.  
```

### Step 2.1 "Compatibility" tab   
```text
Certificate Authority: "Windows Server 2016"
Certificate recipient: "Windows 10/Windows Server 2016"
```   

### Step 2.2 "General" Tab
```text   
Template display name: "Lab-WebServerCertsrv"
Template name: This will auto-fill as Lab-WebServerCertsrv 
Validity period: Set this to your desired duration (e.g., 2 years).
Renewal period: Set this to your desired duration (e.g., 6 weeks).
# Ensure Publish certificate in Active Directory is checked.
```   
### Step 2.3 "Request Handling" Tab
```text
Ensure Allow private key to be exported is NOT checked 
Ensure Archive subject's encryption private key is NOT checked.
For Purpose, select Signature and encryption.
```

### Step 2.4 "Cryptography" Tab
``` text
Provider Category: Select Key Storage Provider.
Algorithm name: Select RSA.
Minimum key size: Ensure this is 4096.
Request hash: Select SHA256 (or higher, like SHA384/SHA512, if your environment supports it).
```

### Step 2.5 "Subject Name" Tab
```text
Ensure Build from this Active Directory information is selected.
Subject name format: Select DNS name.
Include e-mail name in subject: Uncheck.
DNS name: Check DNS name.
# Service principal name (SPN): Check Service principal name (SPN).
User principal name (UPN): Uncheck.
E-mail name: Uncheck.
Include this information in alternate subject name: Check DNS name.
```

### Step 2.6 "Extensions" Tab
``` text
Go to the Extensions tab.
Select Application Policies and click Edit.
Ensure Server Authentication is present. If not, click Add... and add it. Click OK.
Select Key Usage and click Edit.
Ensure Digital signature (and Key encipherment are checked). Click OK.
```

### Step 2.7 "Security"
```text
Go to the Security tab.
Click Add....
Type PKIWebSvc (or LAB\PKIWebSvc) and click Check Names. Select the correct service account and click OK.
With LAB\PKIWebSvc selected, grant the following permissions:
Read: Allow
Enroll: Allow
Autoenroll: Allow (if you plan to use auto-enrollment later)
Also, ensure Domain Computers has Read and Enroll permissions (this is often default for Web Server templates).
Ensure Domain Admins and Enterprise Admins have Full Control.
Click OK to close the template properties.
```

### Step 2.8 Issue the New Template on the CA
```text
Back in the Certificate Authority console, right-click on Certificate Templates.
Select New > Certificate Template to Issue.
From the list, select your newly created template: "Lab-WebServerCertsrv".
Click OK.
✅ Verification
In the Certificate Authority console, under Certificate Templates, you should now see "Lab-WebServerCertsrv" listed.
On Web02.lab.local, add the perform the "New/Certificate Template to Issue" section to ensure this template is availble from both SubCAs

On one of your web servers, open the Certificates MMC (certlm.msc), right-click on Personal > Certificates, and select All Tasks > Request New Certificate.... You should see Custom Web Server 4096 as an available template.
