## tcgtool

Take a path to an efivar and populate the appropriate variable-sized structure for hashing. Based on edk2's [TpmMeasureAndLogData](https://github.com/tianocore/edk2/blob/29cce3356aec6db878ad318c4abeb63aa9e845aa/SecurityPkg/Library/DxeTpmMeasurementLib/DxeTpmMeasurementLib.c#L222).

This is useful for predicting the next value of a PCR that's calculated at boot by firmware, such as PCR7. This allows for sealing a secret such as a disk encryption passphrase using a PCR, while allowing an authenticated system to modify configuration that affects the value of that PCR on the next boot.

### Building

```
make
```

### Example

#### Generating an sha256 digest from an efivar
```
$ ./tcgtool --measure-efivar /sys/firmware/efi/efivars/KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c \
    | sha256sum
737b882fd7667195c8fbc6d1385106b6c94b73d0f4058650db41c37558e66209  -
$ tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements 
---
version: 1
events:
<snip>
- EventNum: 5
  PCRIndex: 7
  EventType: EV_EFI_VARIABLE_DRIVER_CONFIG
  DigestCount: 1
  Digests:
  - AlgorithmId: sha256
    Digest: "737b882fd7667195c8fbc6d1385106b6c94b73d0f4058650db41c37558e66209"
  EventSize: 1374
  Event:
    VariableName: 8be4df61-93ca-11d2-aa0d-00e098032b8c
    UnicodeNameLength: 3
    VariableDataLength: 1336
    UnicodeName: KEK
```

#### Generating a PE/COFF image digest as recorded in the signature database

```
$ ./tcgtool --efibin-hash bootx64.efi | xxd -p -c0
50ab5d6046e00043abb63dd810dd8b233816cb85490d68a0d6fcc49e494dbd1f597ff882fb98fb0f78b8f014ddcb642d
$ tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements
<snip>
- EventNum: 29
  PCRIndex: 7
  EventType: EV_EFI_VARIABLE_AUTHORITY
  DigestCount: 4
  Digests:
  - AlgorithmId: sha1
    Digest: "4d7e74e16a33d355cd05c15d163d94fa7d3acbc4"
  - AlgorithmId: sha256
    Digest: "54af58028abfc0e4a362f022a3af66ddcceefa1fefe27c41a5d0ee076b2ef09f"
  - AlgorithmId: sha384
    Digest: "684c2ea5965df0f5fe706f214424d7fda519a94d062614a4b9585ec5bb487557f822dfcab0de342ae3c3b04d76f3a466"
  - AlgorithmId: sha512
    Digest: "9c86059d6da1621a3fb23eced3a2ab3f41f15bdc3bd3fc3d05ce774cd4aac8f4ab477f0e75ceb1fbdf5c3b0cf077acd452d8357e137c94f963e85e81a4db29ce"
  EventSize: 84
  Event:
    VariableName: d719b2cb-3d3a-4596-a3bc-dad00e67656f
    UnicodeNameLength: 2
    VariableDataLength: 48
    UnicodeName: db
    VariableData: "50ab5d6046e00043abb63dd810dd8b233816cb85490d68a0d6fcc49e494dbd1f597ff882fb98fb0f78b8f014ddcb642d"
```
