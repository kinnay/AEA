
# AEA File Format
This page describes the file format of Apple Encrypted Archives. The AEA format allows user to compress, encrypt and sign their files. The file extension is generally `.aea`.

## General Structure
Every AEA file is laid out as follows:

* [File header](#file-header)
* Auth data
* Signature
* Random key
* Random salt for [main key](#key-derivation)
* Root header MAC
* [Encrypted root header](#root-header)
* MAC of first cluster
* [Encrypted clusters](#cluster)

Depending on the [profile](#profiles) that is specified in the [header](#file-header), some sections may not be present in the file.

All values are encoded in little-endian byte order.

## File Header
| Offset | Size | Description |
| --- | --- | --- |
| 0x0 | 4 | Magic number (`AEA1`) |
| 0x4 | 3 | [Profile id](#profiles) |
| 0x7 | 1 | Always 0 |
| 0x8 | 4 | Auth data size |

### Profiles
| ID | Description |
| --- | --- |
| 0 | No encryption, signed |
| 1 | Symmetric key encryption |
| 2 | Symmetric key encryption, signed |
| 3 | ECDHE encryption |
| 4 | ECDHE encryption, signed |
| 5 | Scrypt encryption (password based) |

## Root Header
The root header is encrypted with the [root header key](#key-derivation).

| Offset | Size | Description |
| --- | --- | --- |
| 0x0 | 8 | Original file size |
| 0x8 | 8 | Encrypted archive size |
| 0x10 | 4 | Segment size |
| 0x14 | 4 | Segments per cluster |
| 0x18 | 1 | Compression algorithm |
| 0x19 | 1 | Checksum algorithm (0=None, 1=Murmur, 2=SHA-256) |
| 0x1A | 6 | Padding (always 0) |
| 0x20 | 16 | Unknown |

## Cluster
The segment headers are encrypted with the [cluster header key](#key-derivation). The segments are encrypted with the [segment keys](#key-derivation).

| Offset | Size | Description |
| --- | --- | --- |
| 0x0 | 0x2800 | Encrypted [segment headers](#segment-header) |
| 0x2800 | 0x20 | MAC of next cluster header |
| 0x2820 | 0x2000 | Segment MACs |
| 0x4820 | | Encrypted segments |

### Segment Header
| Offset | Size | Description |
| --- | --- | --- |
| 0x0 | 4 | Original size |
| 0x4 | 4 | Encoded size |
| 0x8 | | Checksum |

## Key Derivation
All keys that are used in the AEA format are derived using HKDF-SHA256. The IKM, info and salt depend on the type of key that is generated. Keys come in two flavors:
* 32-byte keys that are used to derive other keys.
* 80-byte keys that are used for encryption and MACs.

The second flavor is laid out as follows:

| Offset | Size | Description |
| --- | --- | --- |
| 0x0 | 32 | HMAC-SHA256 key |
| 0x20 | 32 | AES-CTR key |
| 0x40 | 16 | AES-CTR IV |

The following keys are currently known:

* [Main key](#main-key)
* [Root header key](#root-header-key)
* [Cluster key](#cluster-key)
* [Cluster header key](#cluster-header-key)
* [Segment key](#segment-key)

### Main Key
* **Size:** 32 bytes
* **IKM:** the key that is specified on the command line
* **Salt:** specified at the [beginning of the file](#general-structure) before the root header MAC
* **Purpose:** used to derive the [root header key](#root-header-key) and [cluster keys](#cluster-key)

**Info:**
| Offset | Size | Description |
| --- | --- | --- |
| 0x0 | 7 | `AEA_AMK` |
| 0x7 | 4 | Bytes 4-7 of the [header](#file-header) |

### Root Header Key
* **Size:** 80 bytes
* **IKM:** the [main key](#main-key)
* **Salt:** empty
* **Purpose:** used to encrypt the [root header](#root-header)
* **Info:** `AEA_RHEK`

### Cluster Key
* **Size:** 32 bytes
* **IKM:** the [main key](#main-key)
* **Salt:** empty
* **Purpose:** used to derive the [cluster header key](#cluster-header-key) and [segment keys](#segment-keys)

**Info:**
| Offset | Size | Description |
| --- | --- | --- |
| 0x0 | 6 | `AEA_CK` |
| 0x6 | 4 | Cluster index |

### Cluster Header Key
* **Size:** 80 bytes
* **IKM:** the [cluster key](#cluster-key)
* **Salt:** empty
* **Purpose:** used to encrypt the segment headers in the [cluster](#cluster)
* **Info:** `AEA_CHEK`

### Segment Key
* **Size:** 80 bytes
* **IKM:** the [cluster key](#cluster-key)
* **Salt:** empty
* **Purpose:** used to encrypt a segment of the original file

**Info:**
| Offset | Size | Description |
| --- | --- | --- |
| 0x0 | 6 | `AEA_SK` |
| 0x6 | 4 | Segment index |
