# FPGA Spoof (Broken)
## This project is based on reverse engineering! The original binary file is in bin/白名单3.0.exe

(Because I don't have a FPGA dma device so it's hard for me to test, and it's broken now)

## Internal technique:

Patch the HalpPciMcfgTable and HalpPciMcfgTableCount in the ntoskrnl.exe to make the pci device undetectable