import os
print("[i] Current working directory:", os.getcwd())
from zipfile import ZipFile, BadZipFile
def attempt_extract(zf_handle, password):
   try:
       zf_handle.extractall(pwd=password)
       print(f"[✓] Password found: {password.decode().strip()}")
       return True
   except:
       return False
def main():
   print("[+] Beginning bruteforce...")
   with ZipFile('C:/Users/Cigold/Downloads/cyber-project/Forage Internship/sping zero day attack/EncryptedFilePack/enc.zip') as zf:
       with open('C:/Users/Cigold/Downloads/cyber-project/Forage Internship/sping zero day attack/EncryptedFilePack/rockyou.txt', 'rb') as f:
           for line in f:
               password = line.strip()
               if attempt_extract(zf, password):
                   break
           else:
               print("[-] Password not found in list.")
if __name__ == "__main__":
   main()
