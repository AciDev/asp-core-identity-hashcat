import argparse
import os
import sys
import base64


def get_version(hex_hash):
    hex_version = hex_hash[:2]
    if hex_version == "00":
        version = "2"
    elif hex_version == "01":
        version = "3"
    else:
        print(
            f"Error: Unknown ASP.NET CORE Identity Version: {hex_version}. Check hashes."
        )
        sys.exit(1)
    return version


def get_prf(hex_hash):
    prf_hex = hex_hash[2:10]
    if prf_hex == "00000001":
        prf = "sha256"
    elif prf_hex == "00000002":
        prf = "sha512"
    else:
        print(f"Error: Unknown KeyDerivationPrf algorithm: {prf_hex}. Check hashes. ")
        sys.exit(1)
    return prf


def get_iteration(hex_hash):
    iteration_hex = hex_hash[10:18]
    return int(iteration_hex, 16)


def get_salt_length(hex_hash):
    salt_length_hex = hex_hash[18:26]
    return int(salt_length_hex, 16)


def asp_to_hashcat(hex_hash):
    version = get_version(hex_hash)
    if version == "2":
        hash_start_location = 2
        prf = "sha1"
        iteration = 1000
        salt_length = 16
    elif version == "3":
        hash_start_location = 26
        prf = get_prf(hex_hash)
        iteration = get_iteration(hex_hash)
        salt_length = get_salt_length(hex_hash)
    else:
        sys.exit(1)
    print("#" * 50)
    print(f"[*] KeyDerivationPrf: {prf}")
    print(f"[*] Iteration Count: {iteration}")
    print(f"[*] Salt Length: {salt_length}")
    print("#" * 50)
    salt_end_location = hash_start_location + (salt_length * 2)
    salt_byte = bytearray.fromhex(hex_hash[hash_start_location:salt_end_location])
    subkey_byte = bytearray.fromhex(hex_hash[salt_end_location:])

    salt = base64.b64encode(salt_byte).decode("ascii")
    subkey = base64.b64encode(subkey_byte).decode("ascii")

    hashcat_format = f"{prf}:{iteration}:{salt}:{subkey}\n"

    return hashcat_format


def process_file(input_file, output_file):
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' does not exist.")
        sys.exit(1)
    elif not os.path.isfile(input_file):
        print(f"Error: '{input_file}' is not a file.")
        sys.exit(1)

    try:
        print("[*] Attempting to read file.")
        with open(input_file, "r", encoding="utf-8") as i_file:
            with open(output_file, "a") as o_file:
                for line in i_file.readlines():
                    line = line.rstrip("\n")
                    hex_hash = base64.b64decode(line).hex()
                    print("[*] Attempting conversion.")
                    o_file.write(asp_to_hashcat(hex_hash))
                    print("[*] Successful conversion.")

    except PermissionError:
        print(f"Error: Permission denied to read '{input_file}'.")
        sys.exit(1)
    except UnicodeDecodeError:
        print(f"Error: Unable to decode '{input_file}'. Check file encoding.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file '{input_file}': {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Process ASP.NET Core hashes and outputs them in Hashcat format"
    )

    parser.add_argument("-i", "--input", required=True, help="Hash input file path")
    parser.add_argument(
        "-o", "--output", required=True, help="Hashcat output file path"
    )

    args = parser.parse_args()

    input_file = args.input
    output_file = args.output

    process_file(input_file, output_file)


if __name__ == "__main__":
    main()
