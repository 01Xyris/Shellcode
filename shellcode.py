import pefile
import argparse

parser = argparse.ArgumentParser(description="Tool for carving the shellcode out of a PE file.")
parser.add_argument("EXE", help="PE File to extract data from")
parser.add_argument("--format", choices=["c", "py", "bin"], default="c", help="Format to export the shellcode")
parser.add_argument("--whole-file", action="store_true", help="Convert the entire file, not just the .text section")
args = parser.parse_args()

def format_data(data, output_format):
    with open("shell.txt", "w") as f:
        if output_format == "c":
            f.write("const char shellcode[] = \"")
            for i in range(len(data)):
                f.write(f"\\x{data[i]:02x}")
            f.write("\";")
        elif output_format == "py":
            f.write("shellcode = b\"")
            for i in range(len(data)):
                f.write(f"\\x{data[i]:02x}")
            f.write("\"")

def write_binary(data):
    with open("shell.bin", "wb") as f:
        f.write(data)

if args.whole_file:
    with open(args.EXE, 'rb') as f:
        file_data = f.read()
    
    if args.format == "c" or args.format == "py":
        format_data(file_data, args.format)
    elif args.format == "bin":
        write_binary(file_data)

else:
    pe = pefile.PE(args.EXE)
    text_section = None
    for section in pe.sections:
        if b".text" in section.Name:
            text_section = section
            break

    if text_section is None:
        print("Error: .text section not found!")
        exit(1)

    offset = text_section.PointerToRawData

    with open(args.EXE, 'rb') as f:
        f.seek(offset)
        text_data = f.read(text_section.SizeOfRawData)

        i = len(text_data) - 1
        while i >= 0 and text_data[i] == 0:
            i -= 1
        text_data = text_data[:i+1]

    if args.format == "c" or args.format == "py":
        format_data(text_data, args.format)
    elif args.format == "bin":
        write_binary(text_data)
