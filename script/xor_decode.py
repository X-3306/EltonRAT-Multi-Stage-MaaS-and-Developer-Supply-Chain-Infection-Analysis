import struct

def xor_q(q1, q2):
    return struct.pack('<Q', q1 ^ q2)

pairs = [
    (0x84f752f3c286b414, 0xabd86880b2f2c07c), 
    (0x9cbcfb9f7b0ca38d, 0xf4c892f8557bc2ff), 
    (0x2b21c9d524d29df6, 0x4442bbb057a7ff83), 
    (0xae04e36c55cea76a, 0xc167cd183babd304), 
    (0x36714ae46982c029, 0x401e26bc11daef44), 
    (0xed3e43b286ca622f, 0x984c6ceafe92104a), 
    (0xee380acd7c5e28c6, 0xc15d78ac10385cb5), 
    (0x6429d33908b9da78, 0x054cb1b167dfbf0a), 
    (0x76dcd775d182711d, 0x59b2be14bcad0279), 
    (0x36e753ff051a108f, 0x53c8209a717b62ec),
    (0x37a124c12108eb69, 0x378104a44f618c07)
]

url = b''.join([xor_q(p[0], p[1]) for p in pairs])
print(url.decode('ascii', errors='ignore').rstrip('\x00'))