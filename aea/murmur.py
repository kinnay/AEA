
import struct

MASK = (1 << 64) - 1

def murmur64a(data, seed):
	m = 0xC6A4A7935BD1E995
	r = 47

	h = (seed ^ (len(data) * m)) & MASK

	for i in range(0, len(data) & ~7, 8):
		k = struct.unpack_from("<Q", data, i)[0]
		k = (k * m) & MASK
		k ^= k >> r
		k = (k * m) & MASK
		h ^= k
		h = (h * m) & MASK
	
	if len(data) % 8:
		block = data[len(data) & ~7:].ljust(8, b"\0")
		h ^= struct.unpack("<Q", block)[0]
		h = (h * m) & MASK
	
	h ^= h >> r
	h = (h * m) & MASK
	h ^= h >> r
	return struct.pack("<Q", h)
