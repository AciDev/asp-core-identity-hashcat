# ASP.NET Core Identity Hashcat Converter

The intention of this project is to convert an ASP.NET Core Identity hash into Hashcat format so it can be cracked.

## Running the tool

The tool requires an input file and an output file, the output file will be where the Hashcat formatted ASP.NET Identity tokens are placed. The input file is a multi line file that contains a variety of different ASP.NET Core Identity hashes.

## Support

### Version Support

This project supports the following ASP.NET versions:

- Version 2
- Version 3

### KeyDerivationPrf Support

This project currently supports the following Prf's:

- Sha1
- Sha256
- Sha512
