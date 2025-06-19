import sys
from Crypto.Cipher import ARC4

flag = open(sys.argv[1], 'rb').read().strip()
solution = open(sys.argv[2], 'rb').read().strip()

enc = ARC4.new(key=solution).encrypt(flag)
open(sys.argv[3], 'wb').write(enc)
