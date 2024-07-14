
# AEA File Format
This page describes the file format of Apple Encrypted Archives. The AEA format allows users to compress, encrypt and sign their files. The file extension is generally `.aea`.

## General Structure
Every AEA file is laid out as follows:

* [File header](#file-header)
* [Auth data](#auth-data)
* [Signature](#signature)
* [Random key](#random-key)
* [Random salt](#random-salt)
* [Root header MAC](#root-header-mac)
* [Encrypted root header](#root-header)
* [First cluster header MAC](#first-cluster-header-mac)
* [Data clusters](#data-clusters)

The following concepts are also important:
* [Profiles](#profiles)
* [MAC calculation](#mac-calculation)
* [Key derivation](#key-derivation)

All values are encoded in little-endian byte order.

## File Header
| Offset | Size | Description |
| --- | --- | --- |
| 0x0 | 4 | Magic number (`AEA1`) |
| 0x4 | 3 | [Profile id](#profiles) |
| 0x7 | 1 | [Scrypt strength](#key-derivation) |
| 0x8 | 4 | Auth data size |

## Auth Data
The auth data can be used to add metadata to the file. It is stored right after the [file header](#file-header) and contains either a raw binary blob or a number of key-value pairs. The size of the auth data is specified in the [file header](#file-header). If the auth data contains a list of key-value pairs, every pair is encoded by concatening the key and value with a null byte inbetween, and is prefixed with a 32-bit integer that specifies its size:

```python
def encode(key, value):
    pair = key + b"\0" + value
    return struct.pack("<I", len(pair)) + pair
```

Example: `090000006b65790076616c7565`

There is no padding between key-value pairs or behind the auth data, even if this causes the rest of the file to be unaligned.

## Signature
If the profile uses signing, this section contains an ECDSA signature on NIST P-256. The signature is calculated over the SHA-256 hash of all bytes from the start of the file up to and including the first cluster MAC, with the signature itself set to null bytes. The key is specified on the command line. The signature is padded with null bytes until it is 128 bytes in size.

If the profile uses encryption, the signature is encrypted with the [signature encryption key](#key-derivation) using AES-CTR and a [MAC](#mac-calculation) is appended to it (empty salt).

If the profile does not use signing, this section is empty.

**Note:** even for profiles that use signing, the [aea](https://manpagehub.com/aea) tool supports the creation of unsigned archives. In that case, the signature is filled with null bytes before it is encrypted. Unsigned archives must be signed later in order to become valid.

## Random Key
The purpose of this section depends on the profile.

* **No encryption:** this section contains a random 32-byte key from which the [main key](#key-derivation) is derived.
* **Symmetric or password-based encryption:** this section is empty. The [main key](#key-derivation) is derived from the key or password that is specified on the command line.
* **Asymmetric encryption:** this section contains the public key of the sender (65 bytes). This can be used by the receiver to calculate the shared secret from which the [main key](#key-derivation) is derived.

## Random Salt
This section contains 32 random bytes. This is the salt that is used to derive the [main key](#key-derivation).

## Root Header MAC
This section contains [MAC](#mac-calculation) of the encrypted [root header](#root-header). The salt contains the [first cluster MAC](#first-cluster-mac) plus the [auth data](#auth-data). The MAC is calculated using the [root header key](#key-derivation).

## Root Header
The root header is encrypted with the [root header key](#key-derivation).

| Offset | Size | Description |
| --- | --- | --- |
| 0x0 | 8 | Original file size |
| 0x8 | 8 | Encrypted archive size |
| 0x10 | 4 | Segment size |
| 0x14 | 4 | Segments per [cluster](#data-clusters) |
| 0x18 | 1 | [Compression algorithm](#compression-algorithms) |
| 0x19 | 1 | Checksum algorithm (0=None, 1=Murmur, 2=SHA-256) |
| 0x1A | 22 | Always 0 |

The segment size must be at least `0x4000` (16 KB) and is set to `0x100000` (1 MB) by default. The segments per cluster must be at least 32 and is set to 256 by default.

### Compression Algorithms
| ID | Description |
| --- | --- |
| `-` | None |
| `4` | LZ4 |
| `b` | LZBITMAP |
| `e` | LZFSE|
| `f` | LZVN |
| `x` | LZMA |
| `z` | ZLIB |

## First Cluster Header MAC
This section contains the [MAC](#mac-calculation) of the encrypted segment headers of the first [cluster header](#data-clusters). The salt is the remaining part of the first [cluster header](#data-clusters). The key is the [cluster header key](#key-derivation).

## Data Clusters
Large files are divided into multiple clusters, each of which is divided into multiple segments. This is done such that decryption of the file can be parallelized across threads.

A data cluster contains the following sections:
* A list of encrypted [segment headers](#segment-headers)
* The next cluster header MAC
* A list that contains the MAC of each segment
* A list of encrypted segments

The number of entries in each list depends on the number of segments per cluster that is specified in the [root header](#root-header).

The segment headers are encrypted with the [cluster header key](#key-derivation). The segments are encrypted with the [segment keys](#key-derivation).

The next cluster header MAC is [calculated](#mac-calculation) over the encrypted segment headers of the next cluster header. The salt the remaining part of the next cluster header. The key is the [cluster header key](#key-derivation) of the next cluster header.

In the last cluster header, the next cluster header MAC is set to random bytes.

### Segment Header
| Offset | Size | Description |
| --- | --- | --- |
| 0x0 | 4 | Original size |
| 0x4 | 4 | Compressed size |
| 0x8 | | Checksum |

The checksum is calculated over the decrypted segment data. The compression and checksum algorithm are specified in the [root header](#root-header).

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
| 5 | Password-based encryption |

### Names
| Profile ID | Name |
| --- | --- |
| 0 | `hkdf_sha256_hmac__none__ecdsa_p256` |
| 1 | `hkdf_sha256_aesctr_hmac__symmetric__none` |
| 2 | `hkdf_sha256_aesctr_hmac__symmetric__ecdsa_p256` |
| 3 | `hkdf_sha256_aesctr_hmac__ecdhe_p256__none` |
| 4 | `hkdf_sha256_aesctr_hmac__ecdhe_p256__ecdsa_p256` |
| 5 | `hkdf_sha256_aesctr_hmac__scrypt__none` |

## MAC Calculation
The MAC algorithm is HMAC-SHA256. Before a MAC is calculated, a salt is prepended to the data and the size of the salt is appended to the data as a 64-bit integer:

```python
def mac(key, data, salt):
    data = salt + data + struct.pack("<Q", len(salt))
    return hmac.digest(key, data, "sha256")
```

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

For the main key, a [random salt](#random-salt) is used for key derivation. For all other keys, the salt is empty.

### Main Key
The IKM and info that are used to derive the main key depend on the [profile](#profiles).

* **Type:** key derivation key
* **Purpose:** used to derive all other key derivation keys
* **IKM:** see below
* **Info:** `AEA_AMK`, bytes 4-7 of the [file header](#file-header), the sender's and recipient's public keys (if the profile uses asymmetric encryption), and the signing public key (if the profile uses signing), all concatenated.

The IKM depends on the profile:

* **No encryption** the [random key](#random-key)
* **Symmetric encryption:** the key that is specified on the command-line
* **Asymmetric encryption:** the shared secret that is derived from the sender's and recipient's public/private key using ECDH on NIST P-256
* **Password-based encryption:** the key that is derived from the password using scrypt

For password-based encryption, the cost factor (N) is specified in the [file header](#file-header). It can have one of the following values:

| Value | N |
| ---  | --- |
| 0 | `0x4000` |
| 1 | `0x10000` |
| 2 | `0x40000` |
| 3 | `0x100000` |

The official AEA tool always sets it to 0.

When password-based encryption is used, a [new 64-byte salt](#scrypt-salt) is generated from the [random salt](#random-salt). The first 32 bytes are used as the salt for the scrypt algorithm. The next 32 bytes are used as the salt for the HKDF algorithm.

### Scrypt Salt
* **Type:** 64-byte salt
* **Purpose:** used as a salt for [main key](#main-key) derivation
* **IKM:** the [random salt](#random-salt)
* **Info:** `AEA_SCRYPT`

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
* **Purpose:** used to encrypt the segment headers in the [cluster](#data-clusters)
* **IKM:** the [cluster key](#cluster-key)
* **Info:** `AEA_CHEK`

### Segment Key
* **Tpye:** data key
* **Purpose:** used to encrypt a segment of the original file
* **IKM:** the [cluster key](#cluster-key)
* **Info:** `AEA_SK` plus the segment index as 32-bit integer
