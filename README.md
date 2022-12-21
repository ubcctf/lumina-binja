# lumina-binja
IDA's [Lumina](https://hex-rays.com/products/ida/lumina/) feature, reimplemented for Binary Ninja

**CURRENTLY IN ACTIVE DEVELOPMENT - NOTHING IS FULLY STABLE YET**

## Features
 - Compatible with existing public Lumina databases (both official[^1] and unofficial), including TLS support
 - Signatures largely match IDA's implementation, enabling cross-diassembler collaboration (~85% accuracy, including discrepancies in analysis between disassemblers)
 - Supported Architectures:
   - [x] x86 / x86_64
   - [ ] ARM / AArch64
   
   and more to come!
 - Supported metadata types:
   - [x] function names
   - [x] comments
   - [ ] stack frame info (e.g. variable names, stack offsets, types)
   - [ ] function type info

## Credits
 - [Lumen](https://github.com/naim94a/lumen) for most of the RPC protocol reversing
 - [Synactiv's blog](https://www.synacktiv.com/en/publications/investigating-ida-lumina-feature.html) for a high level overview on how Lumina works

**Maple Bacon maintainers:**
 - [@nneonneo](https://github.com/nneonneo) for metadata reversing and implementation
 - [@desp](https://github.com/despawningbone) for signature generation reversing, and stitching everything together

[^1]: Provided that you have specified a valid IDA license file as the key file in the settings, along the valid certificate to connect to `lumina.hex-rays.com`, as obtainable [from official sources](https://hex-rays.com/products/ida/lumina/lumina-cert-20191010/).