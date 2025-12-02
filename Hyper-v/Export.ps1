### Snapshot
# List your lab VMs (adjust list if needed)
$labVMs = "DC1","DC2","File1","File2","SubCA1","SubCA2","Web01","Web02","OCSP1","OCSP2","CARoot1"

# Create a checkpoint on each VM
foreach ($vm in $labVMs) {
    Checkpoint-VM -Name $vm -SnapshotName "Domain Joined Clean"
}

### Export
$labVMs = "DC1","DC2","File1","File2","SubCA1","SubCA2","Web01","Web02","OCSP1","OCSP2","CARoot1"
$exportPath = "F:\Hyper-v\Exports\PKILab-Working-OCSP"
New-Item -Path $exportPath -ItemType Directory -Force | Out-Null

foreach ($vm in $labVMs) {
    Export-VM -Name $vm -Path $exportPath
}

