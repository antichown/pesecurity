import os.path
import sys
import pefile
import os
import colorama


class PESecurity:

  IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
  IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
  IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
  IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000

  def __init__(self,pe):
    self.pe = pe

  def aslr(self):
    return bool(self.pe.OPTIONAL_HEADER.DllCharacteristics & self.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)

  def dep(self):
    return bool(self.pe.OPTIONAL_HEADER.DllCharacteristics & self.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)

  def seh(self):
    return bool(self.pe.OPTIONAL_HEADER.DllCharacteristics & self.IMAGE_DLLCHARACTERISTICS_NO_SEH)

  def CFG(self):
    return bool(self.pe.OPTIONAL_HEADER.DllCharacteristics & self.IMAGE_DLLCHARACTERISTICS_GUARD_CF)


def main():
  print "-- PESecurity by 0x94 --"
  colorama.init(autoreset=True)
  directory=os.environ["ProgramFiles"]+r"\Acunetix 11\core"
  for dirpath, dirnames, filenames in os.walk(directory):
    for filename in [f for f in filenames if f.endswith(".exe")]:
      file_check=os.path.join(directory, filename)
      try:
        if os.path.isfile(file_check):
          pe = pefile.PE(file_check,True)
          ps = PESecurity(pe)
          print file_check
          if ps.aslr():
            print colorama.Fore.GREEN+"[+] ASLR Enabled"
          else:
            print colorama.Fore.RED+"[-] ASLR Not Enabled"

          if ps.dep():
            print colorama.Fore.GREEN+"[+] DEP Enabled"
          else:
            print colorama.Fore.RED+"[-] DEP Not Enabled"

          if ps.seh():
            print colorama.Fore.GREEN+"[+] SEH Enabled"
          else:
            print colorama.Fore.RED+"[-] SEH Not Enabled"

          if ps.CFG():
            print colorama.Fore.GREEN+"[+] CFG Enabled"
          else:
            print colorama.Fore.RED+"[-] CFG Not Enabled"
        else:
          print "File '%s' not found!" % file_check      
      except pefile.PEFormatError:
        pass 

    

if __name__ == '__main__':
  main()