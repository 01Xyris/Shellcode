import subprocess
import re
import os
import sys


CPP_FILE = 'download.cpp'
ASM_FILE = 'download.asm'
OBJ_FILE = 'dl.obj'
FINAL_EXE = 'dl.exe'
PY_SCRIPT = 'shellcode.py'
OUT_ASM = 'dl.asm'

def run_command(command, error_message):
    """Run a system command and check for errors."""
    result = subprocess.run(command, shell=True)
    if result.returncode != 0:
        print(f"{error_message}")
        sys.exit(1)




print(f"Compiling {CPP_FILE} with cl.exe")
run_command(f"cl.exe /c /FA /GS- {CPP_FILE}", "Compilation failed.")


print(f"Running masm_shc.exe to convert {ASM_FILE} to assembly")
run_command(f"masm_shc.exe {ASM_FILE} {OUT_ASM}", "Shellcode conversion failed.")


print(f"Assembling the {OUT_ASM} with ml.exe")
run_command(f"ml /c /Cx /coff {OUT_ASM}", "Assembly failed.")


print(f"Linking {OBJ_FILE} into {FINAL_EXE}")
run_command(f"link /subsystem:console /entry:main {OBJ_FILE}", "Linking failed.")


print(f"Running Python script {PY_SCRIPT} to generate final shellcode executable\n")
run_command(f"python {PY_SCRIPT} {FINAL_EXE}", "Python script execution failed.")
