
# Module: <code>aea</code>

This module implements the Apple Encrypted Archive format.

## API Reference

<code>**def [encode](#encoding)**(data: bytes, \*\*kwargs) -> bytes</code><br>
<code>**def [encode_stream](#encoding)**(input: [BinaryIO](https://docs.python.org/3/library/io.html#binary-i-o), output: [BinaryIO](https://docs.python.org/3/library/io.html#binary-i-o), \*\*kwargs) -> None</code>

<code>**def [decode](#decoding)**(data: bytes, \*\*kwargs) -> bytes</code><br>
<code>**def [decode_stream](#decoding)**(input: [BinaryIO](https://docs.python.org/3/library/io.html#binary-i-o), output: [BinaryIO](https://docs.python.org/3/library/io.html#binary-i-o), \*\*kwargs) -> None</code>

<code>**def [id](#id)**(data: bytes) -> bytes</code>

<code>**class [ProfileType](#profiletype)**([enum.IntEnum](https://docs.python.org/3/library/enum.html#enum.IntEnum))</code><br>
<code>**class [ChecksumAlgorithm](#compressionalgorithm)**([enum.IntEnum](https://docs.python.org/3/library/enum.html#enum.IntEnum))</code><br>
<code>**class [CompressionAlgorithm](#compressionalgorithm)**([enum.IntEnum](https://docs.python.org/3/library/enum.html#enum.StrEnum))</code>

<code>**class ParseError(Exception)**</code><br>
<code>**class SignatureValidationError(ParseError)**</code><br>
<code>**class MACValidationError(ParseError)**</code><br>
<code>**class ChecksumValidationError(ParseError)**</code>

## Encoding
The following keyword argument is optional and specifies how the archive is encrypted and signed. If it is omitted, the profile type is inferred from the remaining keyword arguments:

* <code>profile: [ProfileType](#profiletype)</code>

If one of the following keyword arguments is specified, the archive is encrypted. No more than one of them may be specified:

* `symmetric_key: bytes` (32 bytes)
* `recipient_pub: bytes`
* `password: str`

If the following keyword argument is specified, the archive is signed

* `signature_priv: bytes`

The following keyword arguments may also be specified:

* `auth_data: bytes = b""`
* `segment_size: int = 0x100000`
* `segments_per_cluster: int = 256`
* <code>checksum_algorithm: str = [SHA256](#checksumalgorithm)</code>
* <code>compression_algorithm: int = [LZFSE](#compressionalgorithm)</code>
* `scrypt_strength: int = 0`

## Decoding
For decoding, the profile type is read from the file header. Depending on the profile type, the following keyword arguments may be required:

* `symmetric_key: bytes` (32 bytes)
* `recipient_priv: bytes`
* `password: str`
* `signature_pub: bytes`

The following exceptions may be raised by this function:

* `ParseError`
* `SignatureValidationError`
* `MACValidationError`
* `ChecksumValidationError`

## Id
This method returns the archive id of the file, which is the same as the SHA-256 hash of its prologue.

## ProfileType
`SIGNED = 0`<br>
`SYMMETRIC_ENCRYPTION = 1`<br>
`SYMMETRIC_ENCRYPTION_SIGNED = 2`<br>
`ASYMMETRIC_ENCRYPTION = 3`<br>
`ASYMMETRIC_ENCRYPTION_SIGNED = 4`<br>
`PASSWORD_ENCRYPTION = 5`

## ChecksumAlgorithm
`NONE = 0`<br>
`MURMUR = 1`<br>
`SHA256 = 2`

## CompressionAlgorithm
`NONE = '-'`<br>
`LZ4 = '4'`<br>
`LZBITMAP = 'b'`<br>
`LZFSE = 'e'`<br>
`LZVN = 'f'`<br>
`LZMA = 'x'`<br>
`ZLIB = 'z'`