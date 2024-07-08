
# AEA File Format
This page describes the file format of Apple Encrypted Archives. The AEA format allows user to compress, encrypt and sign their files. The file extension is generally `.aea`.

Everything is encoded in little-endian byte order.

Every AEA file is laid out as follows:

* [File header](#file-header)
* Auth data
* Signature
* Random key
* Random salt
* Root header MAC
* Encrypted root header
* MAC of first cluster
* Encrypted clusters

## File Header
| Offset | Size | Description |
| --- | --- | --- |
| 0x0 | 4 | Magic number (`AEA1`) |
| 0x4 | 3 | [Profile id](#profile-ids) |
| 0x7 | 1 | Unknown |
| 0x8 | 4 | Auth data size |

### Profile IDs
| ID | Description |
| --- | --- |
| 0 | No encryption, signed |
| 1 | Symmetric key encryption |
| 2 | Symmetric key encryption, signed |
| 3 | ECDHE encrpytion |
| 4 | ECDHE encryption, signed |
| 5 | Scrypt encryption (password based) |

## Root Header
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

## Cluster Info
| Offset | Size | Description |
| --- | --- | --- |
| 0x0 | 0x2800 | Encrypted segment headers 

## Segment Header
| Offset | Size | Description |
| --- | --- | --- |
| 0x0 | 4 | Original size |
| 0x4 | 4 | Encoded size |
| 0x8 | | Checksum |
