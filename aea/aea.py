
from aea import murmur
from cryptography import exceptions
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import enum
import hashlib
import hmac
import liblzfse
import lz4.block
import lzma
import os
import struct
import zlib


class ParseError(Exception):
	"""Raised when the AEA archive is corrupted."""

class SignatureValidationError(ParseError):
	"""Raised when the parser encounters an incorrect signature."""

class MACValidationError(ParseError):
	"""Raised when the parser encounters an incorrect MAC."""

class ChecksumValidationError(ParseError):
	"""Raised when the parser encounters an incorrect signature."""


class InputStream:
	def __init__(self, data):
		self.data = data
		self.pos = 0
	
	def tell(self): return self.pos
	def available(self): return len(self.data) - self.pos
	def eof(self): return self.pos == len(self.data)

	def read(self, size):
		if self.available() < size:
			raise ParseError("file is too small or corrupted")
		data = self.data[self.pos : self.pos + size]
		self.pos += size
		return data
	
	def pad(self, size):
		if self.read(size) != bytes(size):
			raise ParseError("file is corrupted")
	
	def u8(self): return self.read(1)[0]
	def u16(self): return struct.unpack("<H", self.read(2))[0]
	def u32(self): return struct.unpack("<I", self.read(4))[0]
	def u64(self): return struct.unpack("<Q", self.read(8))[0]

	def u24(self):
		return self.u16() | (self.u8() << 16)

	def char(self):
		return chr(self.u8())


class OutputStream:
	def __init__(self):
		self.data = bytearray()
		self.pos = 0
	
	def get(self):
		return bytes(self.data)
	
	def seek(self, pos):
		if pos > len(self.data):
			self.data += bytes(pos - len(self.data))
		self.pos = pos
	
	def skip(self, num):
		self.seek(self.pos + num)
	
	def write(self, data):
		self.data[self.pos : self.pos + len(data)] = data
		self.pos += len(data)
	
	def pad(self, size):
		self.write(bytes(size))

	def u8(self, value): self.write(bytes([value]))
	def u16(self, value): self.write(struct.pack("<H", value))
	def u32(self, value): self.write(struct.pack("<I", value))
	def u64(self, value): self.write(struct.pack("<Q", value))

	def u24(self, value):
		self.u16(value & 0xFFFF)
		self.u8(value >> 16)
	
	def char(self, value):
		self.u8(ord(value))


class ProfileType(enum.IntEnum):
	"""Enum that contains the different profile types."""
	SIGNED = 0
	SYMMETRIC_ENCRYPTION = 1
	SYMMETRIC_ENCRYPTION_SIGNED = 2
	ASYMMETRIC_ENCRYPTION = 3
	ASYMMETRIC_ENCRYPTION_SIGNED = 4
	PASSWORD_ENCRYPTION = 5


class ChecksumAlgorithm(enum.IntEnum):
	"""Enum that contains the different checksum algorithms."""
	NONE = 0
	MURMUR = 1
	SHA256 = 2


class CompressionAlgorithm(enum.StrEnum):
	"""Enum that contains the different compression algorithms."""
	NONE = "-"
	LZ4 = "4"
	LZBITMAP = "b"
	LZFSE = "e"
	LZVN = "f"
	LZMA = "x"
	ZLIB = "z"


ProfileTypes = [profile.value for profile in ProfileType]
ChecksumAlgorithms = [algorithm.value for algorithm in ChecksumAlgorithm]
CompressionAlgorithms = [algorithm.value for algorithm in CompressionAlgorithm]


def checksum_none(data):
	return b""

def checksum_murmur(data):
	return murmur.murmur64a(data, 0xE2236FDC26A5F6D2)

def checksum_sha256(data):
	return hashlib.sha256(data).digest()


def compress_none(data):
	return data

def compress_lz4(data):
	return lz4.block.compress(data, store_size=False)

def compress_lzfse(data):
	return liblzfse.compress(data)

def compress_lzma(data):
	return lzma.compress(data)

def compress_zlib(data):
	return zlib.compress(data)


def decompress_none(data, size):
	return data

def decompress_lz4(data, size):
	return lz4.block.decompress(data, size)

def decompress_lzfse(data, size):
	try:
		return liblzfse.decompress(data)
	except liblzfse.error:
		raise ParseError("lzfse decompression failed")

def decompress_lzma(data, size):
	try:
		return lzma.decompress(data)
	except lzma.LZMAError:
		raise ParseError("lzma decompression failed")

def decompress_zlib(data, size):
	try:
		return zlib.decompress(data)
	except zlib.error:
		raise ParseError("zlib decompression failed")


ScryptStrength = {
	0: 0x4000,
	1: 0x10000,
	2: 0x40000,
	3: 0x100000
}

KeySize = {
	ProfileType.SIGNED: 32,
	ProfileType.SYMMETRIC_ENCRYPTION: 80,
	ProfileType.SYMMETRIC_ENCRYPTION_SIGNED: 80,
	ProfileType.ASYMMETRIC_ENCRYPTION: 80,
	ProfileType.ASYMMETRIC_ENCRYPTION_SIGNED: 80,
	ProfileType.PASSWORD_ENCRYPTION: 80
}

SignatureSize = {
	ProfileType.SIGNED: 128,
	ProfileType.SYMMETRIC_ENCRYPTION: 0,
	ProfileType.SYMMETRIC_ENCRYPTION_SIGNED: 160,
	ProfileType.ASYMMETRIC_ENCRYPTION: 0,
	ProfileType.ASYMMETRIC_ENCRYPTION_SIGNED: 160,
	ProfileType.PASSWORD_ENCRYPTION: 0
}

PublicKeySize = {
	ProfileType.SIGNED: 32,
	ProfileType.SYMMETRIC_ENCRYPTION: 0,
	ProfileType.SYMMETRIC_ENCRYPTION_SIGNED: 0,
	ProfileType.ASYMMETRIC_ENCRYPTION: 65,
	ProfileType.ASYMMETRIC_ENCRYPTION_SIGNED: 65,
	ProfileType.PASSWORD_ENCRYPTION: 0
}

ChecksumSize = {
	ChecksumAlgorithm.NONE: 0,
	ChecksumAlgorithm.MURMUR: 8,
	ChecksumAlgorithm.SHA256: 32
}

ChecksumFunctions = {
	ChecksumAlgorithm.NONE: checksum_none,
	ChecksumAlgorithm.MURMUR: checksum_murmur,
	ChecksumAlgorithm.SHA256: checksum_sha256
}

CompressionFunctions = {
	# LZBITMAP and LZVN are unsupported for now
	CompressionAlgorithm.NONE: compress_none,
	CompressionAlgorithm.LZ4: compress_lz4,
	CompressionAlgorithm.LZFSE: compress_lzfse,
	CompressionAlgorithm.LZMA: compress_lzma,
	CompressionAlgorithm.ZLIB: compress_zlib
}

DecompressionFunctions = {
	# LZBITMAP and LZVN are unsupported for now
	CompressionAlgorithm.NONE: decompress_none,
	CompressionAlgorithm.LZ4: decompress_lz4,
	CompressionAlgorithm.LZFSE: decompress_lzfse,
	CompressionAlgorithm.LZMA: decompress_lzma,
	CompressionAlgorithm.ZLIB: decompress_zlib
}


class FileHeader:
	def __init__(self):
		self.profile_id = None
		self.scrypt_strength = None
		self.auth_data_size = None
	
	def encode(self):
		stream = OutputStream()
		stream.write(b"AEA1")
		stream.u24(self.profile_id)
		stream.u8(self.scrypt_strength)
		stream.u32(self.auth_data_size)
		return stream.get()

	def decode(self, data):
		stream = InputStream(data)

		if stream.read(4) != b"AEA1":
			raise ParseError("file has wrong magic number")
		
		self.profile_id = stream.u24()
		self.scrypt_strength = stream.u8()
		self.auth_data_size = stream.u32()

		if self.profile_id not in ProfileTypes:
			raise ParseError("file has invalid profile type")
		
		if self.scrypt_strength not in ScryptStrength:
			raise ParseError("file has invalid scrypt strength field")


class RootHeader:
	def __init__(self):
		self.original_size = None
		self.archive_size = None
		self.segment_size = None
		self.segments_per_cluster = None
		self.compression_algorithm = None
		self.checksum_algorithm = None
	
	def encode(self):
		stream = OutputStream()
		stream.u64(self.original_size)
		stream.u64(self.archive_size)
		stream.u32(self.segment_size)
		stream.u32(self.segments_per_cluster)
		stream.char(self.compression_algorithm)
		stream.u8(self.checksum_algorithm)
		stream.pad(22)
		return stream.get()
	
	def decode(self, data):
		stream = InputStream(data)
		self.original_size = stream.u64()
		self.archive_size = stream.u64()
		self.segment_size = stream.u32()
		self.segments_per_cluster = stream.u32()
		self.compression_algorithm = stream.char()
		self.checksum_algorithm = stream.u8()

		if self.compression_algorithm not in CompressionAlgorithms:
			raise ParseError("file has invalid compression algorithm")
		if self.compression_algorithm not in DecompressionFunctions:
			raise ParseError("file has unsupported compression algorithm")
		
		if self.checksum_algorithm not in ChecksumAlgorithms:
			raise ParseError("file has invalid checksum algorithm")


class KeyDerivation:
	def __init__(self, main_key, key_size):
		self.main_key = main_key
		self.key_size = key_size
	
	def signature_encryption_key(self):
		derivation_key = derive_key(32, self.main_key, b"AEA_SEK")
		return derive_key(self.key_size, derivation_key, b"AEA_SEK2")

	def root_header_key(self):
		return derive_key(self.key_size, self.main_key, b"AEA_RHEK")
	
	def cluster_key(self, index):
		info = b"AEA_CK" + struct.pack("<I", index)
		return derive_key(32, self.main_key, info)
	
	def cluster_header_key(self, cluster_key):
		return derive_key(self.key_size, cluster_key, b"AEA_CHEK")
	
	def segment_key(self, cluster_key, index):
		info = b"AEA_SK" + struct.pack("<I", index)
		return derive_key(self.key_size, cluster_key, info)


def is_symmetric_encryption(profile):
	return profile in [
		ProfileType.SYMMETRIC_ENCRYPTION,
		ProfileType.SYMMETRIC_ENCRYPTION_SIGNED
	]

def is_asymmetric_encryption(profile):
	return profile in [
		ProfileType.ASYMMETRIC_ENCRYPTION,
		ProfileType.ASYMMETRIC_ENCRYPTION_SIGNED
	]

def is_encrypted(profile):
	return profile != ProfileType.SIGNED

def is_signed(profile):
	return profile in [
		ProfileType.SIGNED,
		ProfileType.SYMMETRIC_ENCRYPTION_SIGNED,
		ProfileType.ASYMMETRIC_ENCRYPTION_SIGNED
	]


def infer_profile(symmetric_key, recipient_key, password, signature_key):
	if bool(symmetric_key) + bool(recipient_key) + bool(password) > 1:
		raise TypeError("could not infer profile because more than one type of encryption was specified")
	
	if symmetric_key and signature_key:
		return ProfileType.SYMMETRIC_ENCRYPTION_SIGNED
	elif symmetric_key and not signature_key: 
		return ProfileType.SYMMETRIC_ENCRYPTION
	elif recipient_key and signature_key:
		return ProfileType.ASYMMETRIC_ENCRYPTION_SIGNED
	elif recipient_key and not signature_key:
		return ProfileType.ASYMMETRIC_ENCRYPTION
	elif password and signature_key:
		raise TypeError("could not infer profile because both password and signature_key were specified")
	elif password and not signature_key:
		return ProfileType.PASSWORD_ENCRYPTION
	elif signature_key:
		return ProfileType.SIGNED
	else:
		raise TypeError("at least one key or password must be specified")

def parse_public_key(key, name):
	if key is None:
		raise TypeError("%s is required for the given profile" %name)
	
	try:
		key = serialization.load_pem_public_key(key)
	except Exception:
		raise ValueError("%s is not a valid public key" %name)
	
	if not isinstance(key, ec.EllipticCurvePublicKey):
		raise ValueError("%s is not a valid public key" %name)
	
	return key

def parse_private_key(key, name):
	if key is None:
		raise TypeError("%s is required for the given profile" %name)
	
	try:
		key = serialization.load_pem_private_key(key, None)
	except Exception:
		raise ValueError("%s is not a valid private key" %name)
	
	if not isinstance(key, ec.EllipticCurvePrivateKey):
		raise ValueError("%s is not a valid private key" %name)
	
	return key

def serialize_public_key(key):
	return key.public_bytes(
		serialization.Encoding.X962,
		serialization.PublicFormat.UncompressedPoint
	)

def deserialize_public_key(data):
	return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)

def calculate_mac(key, data, salt):
	data = salt + data + struct.pack("<Q", len(salt))
	return hmac.digest(key, data, "sha256")

def decrypt_and_verify(key, data, salt, mac):
	if mac != calculate_mac(key[:32], data, salt):
		raise MACValidationError("HMAC validation failed")
	
	if len(key) == 80:
		cipher = Cipher(algorithms.AES(key[32:64]), modes.CTR(key[64:]))
		decryptor = cipher.decryptor()
		return decryptor.update(data)
	return data

def encrypt_and_mac(key, data, salt):
	if len(key) == 80:
		cipher = Cipher(algorithms.AES(key[32:64]), modes.CTR(key[64:]))
		encryptor = cipher.encryptor()
		data = encryptor.update(data)
	return data, calculate_mac(key[:32], data, salt)

def derive_key(size, ikm, info, salt=b""):
	hkdf = HKDF(hashes.SHA256(), size, salt, info)
	return hkdf.derive(ikm)

def derive_password_key(password, salt, n):
	kdf = Scrypt(salt, 32, n, 8, 1)
	return kdf.derive(password.encode())

def derive_main_key(
	profile, scrypt_strength, sender_key, recipient_key, signature_key,
	symmetric_key, salt
):
	stream = OutputStream()
	stream.write(b"AEA_AMK")
	stream.u24(profile)
	stream.u8(scrypt_strength)
	if sender_key:
		stream.write(serialize_public_key(sender_key))
	if recipient_key:
		stream.write(serialize_public_key(recipient_key))
	if signature_key:
		stream.write(serialize_public_key(signature_key))
	return derive_key(32, symmetric_key, stream.get(), salt)

def encode(
	data, *, profile=None, symmetric_key=None, recipient_pub=None,
	password=None, signature_pub=None, signature_priv=None, auth_data=b"",
	segment_size=0x100000, segments_per_cluster=256,
	checksum_algorithm=ChecksumAlgorithm.SHA256,
	compression_algorithm=CompressionAlgorithm.LZFSE,
	scrypt_strength=0
):
	"""Encodes the given file into an AEA file."""

	if profile is None:
		profile = infer_profile(
			symmetric_key, recipient_pub, password,
			signature_pub or signature_priv
		)
	
	main_salt = os.urandom(32)

	if profile == ProfileType.SIGNED:
		symmetric_key = os.urandom(32)
	elif is_symmetric_encryption(profile):
		if symmetric_key is None:
			raise TypeError("symmetric_key is required for the given profile")
		if len(symmetric_key) != 32:
			raise ValueError("symmetric_key must contain exactly 32 bytes")
	
	sender_priv = None
	sender_pub = None
	if is_asymmetric_encryption(profile):
		sender_priv = ec.generate_private_key(ec.SECP256R1())
		sender_pub = sender_priv.public_key()
		recipient_pub = parse_public_key(recipient_pub, "recipient_pub")
		symmetric_key = sender_priv.exchange(ec.ECDH(), recipient_pub)
	
	derived_main_salt = main_salt
	if profile == ProfileType.PASSWORD_ENCRYPTION:
		if password is None:
			raise TypeError("password is required for the given profile")
		if scrypt_strength not in ScryptStrength:
			raise ValueError("scrypt_strength is invalid")
		extended_salt = derive_key(64, main_salt, b"AEA_SCRYPT")
		derived_main_salt = extended_salt[32:]
		symmetric_key = derive_password_key(password, extended_salt[:32], ScryptStrength[scrypt_strength])
	elif scrypt_strength != 0:
		raise ValueError("scrypt_strength is invalid for the given profile")
	
	if is_signed(profile):
		if not signature_pub and not signature_priv:
			raise TypeError("signature_pub or signature_priv is required for the given profile")
		elif signature_pub and not signature_priv:
			signature_pub = parse_public_key(signature_pub, "signature_pub")
		elif signature_priv and not signature_pub:
			signature_priv = parse_private_key(signature_priv, "signature_priv")
			signature_pub = signature_priv.public_key()
		else:
			signature_priv = parse_private_key(signature_priv, "signature_priv")
			signature_pub = parse_public_key(signature_pub, "signature_pub")
			if signature_priv.public_key() != signature_pub:
				raise ValueError("signature_priv and signature_pub are not the same key")
	
	if segment_size < 0x4000:
		raise ValueError("segment_size must be at least 0x4000 (16 KB)")
	if segments_per_cluster < 32:
		raise ValueError("segments_per_cluster must be at least 32")
	if checksum_algorithm not in ChecksumAlgorithms:
		raise ValueError("checksum_algorithm is invalid")
	if compression_algorithm not in CompressionAlgorithms:
		raise ValueError("compression_algorithm is invalid")
	if compression_algorithm not in CompressionFunctions:
		raise ValueError("compression_algorithm is not supported")
	
	main_key = derive_main_key(
		profile, scrypt_strength, sender_pub, recipient_pub, signature_pub,
		symmetric_key, derived_main_salt
	)

	key_derivation = KeyDerivation(main_key, KeySize[profile])

	checksum_size = ChecksumSize[checksum_algorithm]
	cluster_size = segment_size * segments_per_cluster
	cluster_count = (len(data) + cluster_size - 1) // cluster_size

	clusters = []
	next_cluster_mac = os.urandom(32)

	for cluster_index in reversed(range(cluster_count)):
		cluster_offset = cluster_index * cluster_size
		cluster_key = key_derivation.cluster_key(cluster_index)
		cluster_header_key = key_derivation.cluster_header_key(cluster_key)

		segment_headers = b""
		segment_macs = b""
		segment_blob = b""
		for segment_index in range(segments_per_cluster):
			segment_offset = cluster_offset + segment_index * segment_size
			segment_data = data[segment_offset : segment_offset + segment_size]
			if segment_data:
				checksum = ChecksumFunctions[checksum_algorithm](segment_data)
				compressed_data = CompressionFunctions[compression_algorithm](segment_data)
				if len(compressed_data) >= len(segment_data):
					compressed_data = segment_data
				segment_header = struct.pack("<II", len(segment_data), len(compressed_data)) + checksum

				segment_key = key_derivation.segment_key(cluster_key, segment_index)
				segment_data, segment_mac = encrypt_and_mac(segment_key, compressed_data, b"")
			else:
				segment_header = bytes(8 + checksum_size)
				segment_mac = os.urandom(32)
			segment_headers += segment_header
			segment_macs += segment_mac
			segment_blob += segment_data
		
		salt = next_cluster_mac + segment_macs
		segment_headers, cluster_mac = encrypt_and_mac(cluster_header_key, segment_headers, salt)

		clusters.append(segment_headers + next_cluster_mac + segment_macs + segment_blob)

		next_cluster_mac = cluster_mac
	
	cluster_data = b"".join(reversed(clusters))

	prologue_size = 12 + len(auth_data)
	prologue_size += SignatureSize[profile]
	prologue_size += PublicKeySize[profile]
	prologue_size += 32 + 32 + 48 + 32

	root_header = RootHeader()
	root_header.original_size = len(data)
	root_header.archive_size = prologue_size + len(cluster_data)
	root_header.segment_size = segment_size
	root_header.segments_per_cluster = segments_per_cluster
	root_header.checksum_algorithm = checksum_algorithm
	root_header.compression_algorithm = compression_algorithm

	root_header_key = key_derivation.root_header_key()
	root_header_salt = next_cluster_mac + auth_data
	root_header_data, root_header_mac = encrypt_and_mac(
		root_header_key, root_header.encode(), root_header_salt
	)

	header = FileHeader()
	header.profile_id = profile
	header.scrypt_strength = scrypt_strength
	header.auth_data_size = len(auth_data)

	public_key = b""
	if profile == ProfileType.SIGNED:
		public_key = symmetric_key
	elif is_asymmetric_encryption(profile):
		public_key = serialize_public_key(sender_pub)

	stream = OutputStream()
	stream.write(header.encode())
	stream.write(auth_data)
	stream.skip(SignatureSize[profile])
	stream.write(public_key)
	stream.write(main_salt)
	stream.write(root_header_mac)
	stream.write(root_header_data)
	stream.write(next_cluster_mac)

	if is_signed(profile):
		if signature_priv:
			signature = signature_priv.sign(stream.get(), ec.ECDSA(hashes.SHA256()))
			signature = signature.ljust(128, b"\0")
		else:
			signature = bytes(128)
		
		if is_encrypted(profile):
			signature_key = key_derivation.signature_encryption_key()
			signature, mac = encrypt_and_mac(signature_key, signature, b"")
			signature += mac
	
		stream.seek(12 + len(auth_data))
		stream.write(signature)

	return stream.get() + cluster_data

def decode(
	data, *, symmetric_key=None, recipient_priv=None, password=None,
	signature_pub=None
):
	"""Decodes the given AEA file."""

	stream = InputStream(data)

	header = FileHeader()
	header.decode(stream.read(12))

	auth_data = stream.read(header.auth_data_size)
	signature_start = stream.tell()
	signature = stream.read(SignatureSize[header.profile_id])
	signature_end = stream.tell()
	public_key = stream.read(PublicKeySize[header.profile_id])
	main_salt = stream.read(32)
	root_header_mac = stream.read(32)
	root_header_data = stream.read(48)
	cluster_mac = stream.read(32)

	if header.profile_id == ProfileType.SIGNED:
		symmetric_key = public_key
	elif is_symmetric_encryption(header.profile_id):
		if symmetric_key is None:
			raise TypeError("symmetric_key is required for the given profile")
		if len(symmetric_key) != 32:
			raise ValueError("symmetric_key must contain exactly 32 bytes")
	
	sender_pub = None
	recipient_pub = None
	if is_asymmetric_encryption(header.profile_id):
		recipient_priv = parse_private_key(recipient_priv, "recipient_priv")
		recipient_pub = recipient_priv.public_key()
		sender_pub = deserialize_public_key(public_key)
		symmetric_key = recipient_priv.exchange(ec.ECDH(), sender_pub)

	if header.profile_id == ProfileType.PASSWORD_ENCRYPTION:
		if password is None:
			raise TypeError("password is required for the given profile")
		extended_salt = derive_key(64, main_salt, b"AEA_SCRYPT")
		main_salt = extended_salt[32:]
		symmetric_key = derive_password_key(
			password, extended_salt[:32],
			ScryptStrength[header.scrypt_strength]
		)

	if is_signed(header.profile_id):
		signature_pub = parse_public_key(signature_pub, "signature_pub")
	else:
		signature_pub = None

	main_key = derive_main_key(
		header.profile_id, header.scrypt_strength, sender_pub, recipient_pub,
		signature_pub, symmetric_key, main_salt
	)

	key_derivation = KeyDerivation(main_key, KeySize[header.profile_id])

	if is_signed(header.profile_id):
		if is_encrypted(header.profile_id):
			key = key_derivation.signature_encryption_key()
			signature = decrypt_and_verify(key, signature[:128], b"", signature[128:])
		
		# The python cryptography library does not permit trailing null bytes in
		# the signature so we have to remove them
		signature = signature[:signature[1]+2]

		end = stream.tell()
		prologue = data[:signature_start] + bytes(signature_end - signature_start) + data[signature_end:end]
		try:
			signature_pub.verify(signature, prologue, ec.ECDSA(hashes.SHA256()))
		except exceptions.InvalidSignature:
			raise SignatureValidationError("signature validation failed")
	
	root_header_key = key_derivation.root_header_key()
	root_header_salt = cluster_mac + auth_data
	root_header_data = decrypt_and_verify(
		root_header_key, root_header_data, root_header_salt, root_header_mac
	)

	root_header = RootHeader()
	root_header.decode(root_header_data)

	if root_header.original_size == 0:
		return b""

	segment_header_size = ChecksumSize[root_header.checksum_algorithm] + 8

	cluster_index = 0
	output_data = b""
	while True:
		cluster_key = key_derivation.cluster_key(cluster_index)
		cluster_header_key = key_derivation.cluster_header_key(cluster_key)

		segment_headers = stream.read(segment_header_size * root_header.segments_per_cluster)
		next_cluster_mac = stream.read(32)
		segment_macs = stream.read(32 * root_header.segments_per_cluster)

		segment_headers = decrypt_and_verify(
			cluster_header_key, segment_headers,
			next_cluster_mac + segment_macs, cluster_mac
		)

		for i in range(root_header.segments_per_cluster):
			segment_header = segment_headers[segment_header_size*i:segment_header_size*(i+1)]
			original_size, compressed_size = struct.unpack_from("<II", segment_header)
			checksum = segment_header[8:]

			segment_data = stream.read(compressed_size)
			segment_mac = segment_macs[32*i:32*(i+1)]
			
			segment_key = key_derivation.segment_key(cluster_key, i)
			segment_data = decrypt_and_verify(segment_key, segment_data, b"", segment_mac)

			if original_size > compressed_size:
				segment_data = DecompressionFunctions[root_header.compression_algorithm](segment_data, original_size)

			if len(segment_data) != original_size:
				raise ParseError("segment has incorrect size after decompression")
			
			calculated_checksum = ChecksumFunctions[root_header.checksum_algorithm](segment_data)
			if calculated_checksum != checksum:
				raise ChecksumValidationError("checksum validation failed")

			output_data += segment_data

			if len(output_data) == root_header.original_size:
				return output_data
		
		cluster_mac = next_cluster_mac
		cluster_index += 1

def id(data):
	header = FileHeader()
	header.decode(data[:12])

	size = 12 + header.auth_data_size
	size += SignatureSize[header.profile_id]
	size += PublicKeySize[header.profile_id]
	size += 32 + 32 + 48 + 32

	return hashlib.sha256(data[:size]).digest()
