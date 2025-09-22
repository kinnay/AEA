# Apple Encrypted Archive Tool
Apple Encrypted Archive (AEA) is a proprietary archive format that supports compression, encryption and signatures. It is designed such that the decoding of large files can be parallelized across threads.

This repository provides:
* A Python library to work with AEA files in code.
* Documentation that describes the AEA file format.

Installation: `pip3 install python-aea`.

### Documentation
* [The AEA file format](https://github.com/kinnay/AEA/blob/main/FORMAT.md)
* [The classes and functions in this package](https://aea.readthedocs.io)

### Contributing
Feel free to open a pull request or issue on GitHub. Please try to follow the current style as much as possible.

### Example Usage
The following example decodes an AEA file that was encrypted and signed:

```python
import aea

with open("symmetric_key.bin", "rb") as f: symmetric_key = f.read()
with open("signature_pub.pem", "rb") as f: signature_pub = f.read()

with open("archive.aea", "rb") as f:
    archive = f.read()

plaintext = aea.decode(archive, symmetric_key=symmetric_key, signature_pub=signature_pub)
```

More examples can be found in the [tests](https://github.com/kinnay/AEA/blob/main/tests/test_aea.py) that have been written for this package.
