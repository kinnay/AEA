
# AEA File Format
This page describes the file format of Apple Encrypted Archives. The AEA format allows users to compress, encrypt and sign their files. The file extension is generally `.aea`.

## General Structure
Every AEA file is laid out as follows:

* [File header](#file-header)
* [Auth data](#auth-data)
* [Signature](#signature)
* [Random key](#random-key)
* [Random salt](#random-salt)
* Root header MAC
* [Encrypted root header](#root-header)
* MAC of first cluster
* [Encrypted clusters](#cluster)

The following concepts are also important:
* [Profiles](#profiles)
* [Key derivation](#key-derivation)

All values are encoded in little-endian byte order.

## File Header
| Offset | Size | Description |
| --- | --- | --- |
| 0x0 | 4 | Magic number (`AEA1`) |
| 0x4 | 3 | [Profile id](#profiles) |
| 0x7 | 1 | Always 0 |
| 0x8 | 4 | Auth data size |

## Auth Data
The auth data is stored right after the [file header](#file-header) and contains either a raw binary blob or a number of key-value pairs. The size of the auth data is specified in the [file header](#file-header). If the auth data contains a list of key-value pairs, every pair is encoded by concatening the key and value with a null byte inbetween, and is prefixed with a 32-bit integer that specifies its size:

```python
def encode(key, value):
    pair = key + b"\0" + value
    return struct.pack("<I", len(pair)) + pair
```

Example: `090000006b65790076616c7565`

There is no padding between key-value pairs or behind the auth data, even if this causes the rest of the file to be unaligned.

## Signature
If the profile uses signing, this section contains an ECDSA signature. The signature is calculated over the SHA-256 hash of all bytes from the start of the file up to and including the first cluster MAC, with the signature itself set to null bytes. The key is specified on the command line. The signature is padded with null bytes until it is 128 bytes in size.

If the profile uses encryption, the signature is encrypted with the [signature encryption key](#key-derivation) using AES-CTR and a HMAC-SHA256 is appended to it.

If the profile does not use signing, this section is empty.

**Note:** even for profiles that use signing, the [aea](https://manpagehub.com/aea) tool supports the creation of unsigned archives. In that case, the signature is filled with null bytes. Unsigned archives must be signed later in order to become valid.

## Random Key
If the profile uses encryption, this section is empty and the key is specified on the command line.

If the profile does not use encryption, this section contains a random 32-byte key, and the [main key](#key-derivation) is derived from the random key instead of a user-specified key.

## Random Salt
This section contains 32 random bytes. This is the salt that is used to derive the [main key](#key-derivation).

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

## Profiles
The AEA file format supports different profiles, each of which specifies a different type of encryption and signatures. The following tables describe the different profiles:

* [Purpose](#purpose)
* [Names](#names)

### Purpose
| Profile ID | Purpose |
| --- | --- |
| 0 | No encryption, signed |
| 1 | Symmetric encryption |
| 2 | Symmetric encryption, signed |
| 3 | Asymmetric encryption |
| 4 | Asymmetric encryption, signed |
| 5 | Scrypt encryption (password based) |

### Names
| Profile ID | Name |
| --- | --- |
| 0 | `hkdf_sha256_hmac__none__ecdsa_p256` |
| 1 | `hkdf_sha256_aesctr_hmac__symmetric__none` |
| 2 | `hkdf_sha256_aesctr_hmac__symmetric__ecdsa_p256` |
| 3 | `hkdf_sha256_aesctr_hmac__ecdhe_p256__none` |
| 4 | `hkdf_sha256_aesctr_hmac__ecdhe_p256__ecdsa_p256` |
| 5 | `hkdf_sha256_aesctr_hmac__scrypt__none` |

## Key Derivation
All keys that are used in the AEA format are derived using HKDF-SHA256. The IKM, info and salt depend on the type of key that is generated. Keys come in two flavors:
* **Key derivation keys:** 32-byte keys that are used to derive other keys
* **Data keys:** 32-byte or 80-byte keys that are used for encryption and MACs

If the [profile](#profiles) does not use encryption, a data key consists of 32 bytes and is only used for HMACs.

If the [profile](#profiles) uses encryption, a data key consists of the following 80 bytes:

| Offset | Size | Description |
| --- | --- | --- |
| 0x0 | 32 | HMAC-SHA256 key |
| 0x20 | 32 | AES-CTR key |
| 0x40 | 16 | AES-CTR IV |

The following keys are used in AEA files:

* [Main key](#main-key)
* [Signature encryption key derivation key](#signature-encryption-key-derivation-key)
* [Signature encryption key](#signature-encryption-key)
* [Root header key](#root-header-key)
* [Cluster key](#cluster-key)
* [Cluster header key](#cluster-header-key)
* [Segment key](#segment-key)

For the main key, the salt is specified at the [beginning of the file](#general-structure) before the root header MAC. For all other keys, the salt is empty.

### Main Key
* **Type:** key derivation key
* **Purpose:** used to derive the [root header key](#root-header-key) and [cluster keys](#cluster-key)
* **IKM:** the key that is specified on the command line
* **Info:** `AEA_AMK` plus bytes 4-7 of the [file header](#file-header)

### Signature Encryption Key Derivation Key
* **Type:** key derivation key
* **Purpose:** used to derive the [signature encryption key](#signature-encryption-key)
* **IKM:** the [main key](#main-key)
* **Info:** `AEA_SEK`

### Signature Encryption Key
* **Type:** data key
* **Purpose:** used to encrypt the [file signature](#signature)
* **IKM:** the [signature encryption key derivation key](#signature-encryption-key-derivation-key)
* **Info:** `AEA_SEK2`

### Root Header Key
* **Type:** data key
* **Purpose:** used to encrypt the [root header](#root-header)
* **IKM:** the [main key](#main-key)
* **Info:** `AEA_RHEK`

### Cluster Key
* **Type:** key derivation key
* **Purpose:** used to derive the [cluster header key](#cluster-header-key) and [segment keys](#segment-keys)
* **IKM:** the [main key](#main-key)
* **Info:** `AEA_CK` plus the cluster index as 32-bit integer

### Cluster Header Key
* **Type:** data key
* **Purpose:** used to encrypt the segment headers in the [cluster](#cluster)
* **IKM:** the [cluster key](#cluster-key)
* **Info:** `AEA_CHEK`

### Segment Key
* **Tpye:** data key
* **Purpose:** used to encrypt a segment of the original file
* **IKM:** the [cluster key](#cluster-key)
* **Info:** `AEA_SK` plus the segment index as 32-bit integer
