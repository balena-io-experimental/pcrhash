## pcrhash

Take a path to an efivar and populate the appropriate variable-sized structure for hashing. Based on edk2's [TpmMeasureAndLogData](https://github.com/tianocore/edk2/blob/29cce3356aec6db878ad318c4abeb63aa9e845aa/SecurityPkg/Library/DxeTpmMeasurementLib/DxeTpmMeasurementLib.c#L222).

This is useful for predicting the next value of a PCR that's calculated at boot by firmware, such as PCR7. This allows for sealing a secret such as a disk encryption passphrase using a PCR, while allowing an authenticated system to modify configuration that affects the value of that PCR on the next boot.

### Building

```
make pcrhash
```

### Example

```
$ ./pcrhash /sys/firmware/efi/efivars/KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c \
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
