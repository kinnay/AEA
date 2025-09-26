
## Changelog

### 1.1.0
This method improves the performance of encoding/decoding archives by avoiding unnecessary copies of data in memory (thanks to [BrainStackOverFlow](https://github.com/kinnay/AEA/pull/1) for this suggestion).

For 256 MB archives, decoding is now 40x faster, and encoding is about 6-7x faster. The bigger the archive, the greater the speedup.

In addition, `decode_stream` and `encode_stream` functions were added. This allows archives to be decoded without loading the entire archive into memory.

*Released on 2025-09-26*

### 1.0.1
Fixed the license that is specified in `setup.py`.

*Released on 2025-07-16*

### 1.0.0
Initial release.

Supports all variants of the file format except for `LZBITMAP` and `LZVN` compression. Provides functions for encoding, decoding and calculating the archive id of an AEA file.

*Released on 2024-07-22*
