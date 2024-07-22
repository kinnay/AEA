
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import aea
import os
import uuid


def serialize_public_key(key):
	return key.public_bytes(
		serialization.Encoding.PEM,
		serialization.PublicFormat.SubjectPublicKeyInfo
	)

def serialize_private_key(key):
	return key.private_bytes(
		serialization.Encoding.PEM,
		serialization.PrivateFormat.PKCS8,
		serialization.NoEncryption()
	)

def make_compressable_text():
	data = b""
	for i in range(256):
		data += bytes([i]) * i
	return data

def test_empty():
	signature_priv = ec.generate_private_key(ec.SECP256R1())
	signature_pub = signature_priv.public_key()

	data = aea.encode(
		b"", profile=aea.ProfileType.SIGNED,
		signature_priv=serialize_private_key(signature_priv)
	)
	assert len(data) == 0x13C

	data = aea.decode(data, signature_pub=serialize_public_key(signature_pub))
	assert data == b""

def test_signed():
	signature_priv = ec.generate_private_key(ec.SECP256R1())
	signature_pub = signature_priv.public_key()
	data = aea.encode(
		b"Hello World!", profile=aea.ProfileType.SIGNED,
		signature_priv=serialize_private_key(signature_priv)
	)
	data = aea.decode(data, signature_pub=serialize_public_key(signature_pub))
	assert data == b"Hello World!"

def test_symmetric_encryption():
	key = os.urandom(32)
	data = aea.encode(
		b"Hello World!", profile=aea.ProfileType.SYMMETRIC_ENCRYPTION,
		symmetric_key=key
	)
	data = aea.decode(data, symmetric_key=key)
	assert data == b"Hello World!"

def test_symmetric_encryption_signed():
	key = os.urandom(32)
	signature_priv = ec.generate_private_key(ec.SECP256R1())
	signature_pub = signature_priv.public_key()
	data = aea.encode(
		b"Hello World!", profile=aea.ProfileType.SYMMETRIC_ENCRYPTION,
		symmetric_key=key, signature_priv=serialize_private_key(signature_priv)
	)
	data = aea.decode(
		data, symmetric_key=key,
		signature_pub=serialize_public_key(signature_pub)
	)
	assert data == b"Hello World!"

def test_asymmetric_encryption():
	recipient_priv = ec.generate_private_key(ec.SECP256R1())
	recipient_pub = recipient_priv.public_key()
	data = aea.encode(
		b"Hello World!", profile=aea.ProfileType.ASYMMETRIC_ENCRYPTION,
		recipient_pub=serialize_public_key(recipient_pub)
	)
	data = aea.decode(data, recipient_priv=serialize_private_key(recipient_priv))
	assert data == b"Hello World!"

def test_asymmetric_encryption_signed():
	recipient_priv = ec.generate_private_key(ec.SECP256R1())
	recipient_pub = recipient_priv.public_key()
	signature_priv = ec.generate_private_key(ec.SECP256R1())
	signature_pub = signature_priv.public_key()
	data = aea.encode(
		b"Hello World!", profile=aea.ProfileType.ASYMMETRIC_ENCRYPTION,
		recipient_pub=serialize_public_key(recipient_pub),
		signature_priv=serialize_private_key(signature_priv)
	)
	data = aea.decode(
		data, recipient_priv=serialize_private_key(recipient_priv),
		signature_pub=serialize_public_key(signature_pub)
	)
	assert data == b"Hello World!"

def test_password():
	password = str(uuid.uuid4())
	data = aea.encode(
		b"Hello World!", profile=aea.ProfileType.PASSWORD_ENCRYPTION,
		password=password
	)
	data = aea.decode(data, password=password)
	assert data == b"Hello World!"

def test_multiple_clusters():
	key = os.urandom(32)
	text = os.urandom(1024 * 1024 * 10)
	data = aea.encode(
		text, profile=aea.ProfileType.SYMMETRIC_ENCRYPTION, symmetric_key=key,
		segment_size=64*1024, segments_per_cluster=32
	)
	data = aea.decode(data, symmetric_key=key)
	assert data == text

def test_auth_data():
	key = os.urandom(32)
	auth_data = os.urandom(128)
	data = aea.encode(
		b"Hello World!", profile=aea.ProfileType.SYMMETRIC_ENCRYPTION,
		symmetric_key=key, auth_data=auth_data
	)
	data = aea.decode(data, symmetric_key=key)
	assert data == b"Hello World!"

def test_checksum_none():
	signature_priv = ec.generate_private_key(ec.SECP256R1())
	signature_pub = signature_priv.public_key()
	data = aea.encode(
		b"Hello World!", signature_priv=serialize_private_key(signature_priv),
		checksum_algorithm=aea.ChecksumAlgorithm.NONE
	)
	data = aea.decode(data, signature_pub=serialize_public_key(signature_pub))
	assert data == b"Hello World!"

def test_checksum_murmur():
	signature_priv = ec.generate_private_key(ec.SECP256R1())
	signature_pub = signature_priv.public_key()
	data = aea.encode(
		b"Hello World!", signature_priv=serialize_private_key(signature_priv),
		checksum_algorithm=aea.ChecksumAlgorithm.MURMUR
	)
	data = aea.decode(data, signature_pub=serialize_public_key(signature_pub))
	assert data == b"Hello World!"

def test_compression_none():
	signature_priv = ec.generate_private_key(ec.SECP256R1())
	signature_pub = signature_priv.public_key()
	text = make_compressable_text()
	data = aea.encode(
		text, signature_priv=serialize_private_key(signature_priv),
		compression_algorithm=aea.CompressionAlgorithm.NONE
	)
	data = aea.decode(data, signature_pub=serialize_public_key(signature_pub))
	assert data == text

def test_compression_lz4():
	signature_priv = ec.generate_private_key(ec.SECP256R1())
	signature_pub = signature_priv.public_key()
	text = make_compressable_text()
	data = aea.encode(
		text, signature_priv=serialize_private_key(signature_priv),
		compression_algorithm=aea.CompressionAlgorithm.LZ4
	)
	data = aea.decode(data, signature_pub=serialize_public_key(signature_pub))
	assert data == text

def test_compression_lzfse():
	signature_priv = ec.generate_private_key(ec.SECP256R1())
	signature_pub = signature_priv.public_key()
	text = make_compressable_text()
	data = aea.encode(
		text, signature_priv=serialize_private_key(signature_priv),
		compression_algorithm=aea.CompressionAlgorithm.LZFSE
	)
	data = aea.decode(data, signature_pub=serialize_public_key(signature_pub))
	assert data == text

def test_compression_lzma():
	signature_priv = ec.generate_private_key(ec.SECP256R1())
	signature_pub = signature_priv.public_key()
	text = make_compressable_text()
	data = aea.encode(
		text, signature_priv=serialize_private_key(signature_priv),
		compression_algorithm=aea.CompressionAlgorithm.LZMA
	)
	data = aea.decode(data, signature_pub=serialize_public_key(signature_pub))
	assert data == text

def test_compression_zlib():
	signature_priv = ec.generate_private_key(ec.SECP256R1())
	signature_pub = signature_priv.public_key()
	text = make_compressable_text()
	data = aea.encode(
		text, signature_priv=serialize_private_key(signature_priv),
		compression_algorithm=aea.CompressionAlgorithm.ZLIB
	)
	data = aea.decode(data, signature_pub=serialize_public_key(signature_pub))
	assert data == text
