
import setuptools

long_description = \
	"This package implements the Apple Encrypted Archive format."

setuptools.setup(
	name = "python-aea",
	version = "1.0.1",
	description = "Apple Encrypted Archive tools",
	long_description = long_description,
	author = "Yannik Marchand",
	author_email = "ymarchand@me.com",
	url = "https://github.com/kinnay/AEA",
	license = "MIT",
	packages = ["aea"],
	entry_points = {
		"console_scripts": [
			"aea = aea.cli:cli"
		]
	},
	install_requires = [
		"click",
		"cryptography",
		"lz4",
		"pyliblzfse"
	]
)
