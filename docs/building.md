# Build Notes

## Linux

For Linux builds, our desired output is a portable binary that is drop-in
compatible on any modern Linux distribution.

The only runtime dependency we require is libc and its auxiliary libraries.

This means we statically link with all dependencies except libc. This includes
the C++ standard library and all dependencies declared in Bazel.

Building on Ubuntu 16.04 in this way yields a target glibc version of 2.17 or
greater.

As an example output:

```
> ldd -v bazel-bin/kmsp11/main/libkmsp11.so
        linux-vdso.so.1 =>  (0x00007fffb0ff3000)
        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f56c3185000)
        libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f56c2e7c000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f56c2ab2000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f56c4462000)

        Version information:
        bazel-bin/kmsp11/main/libkmsp11.so:
                ld-linux-x86-64.so.2 (GLIBC_2.3) => /lib64/ld-linux-x86-64.so.2
                libm.so.6 (GLIBC_2.2.5) => /lib/x86_64-linux-gnu/libm.so.6
                libpthread.so.0 (GLIBC_2.12) => /lib/x86_64-linux-gnu/libpthread.so.0
                libpthread.so.0 (GLIBC_2.3.3) => /lib/x86_64-linux-gnu/libpthread.so.0
                libpthread.so.0 (GLIBC_2.3.2) => /lib/x86_64-linux-gnu/libpthread.so.0
                libpthread.so.0 (GLIBC_2.2.5) => /lib/x86_64-linux-gnu/libpthread.so.0
                libc.so.6 (GLIBC_2.16) => /lib/x86_64-linux-gnu/libc.so.6
                libc.so.6 (GLIBC_2.9) => /lib/x86_64-linux-gnu/libc.so.6
                libc.so.6 (GLIBC_2.10) => /lib/x86_64-linux-gnu/libc.so.6
                libc.so.6 (GLIBC_2.17) => /lib/x86_64-linux-gnu/libc.so.6
                libc.so.6 (GLIBC_2.4) => /lib/x86_64-linux-gnu/libc.so.6
                libc.so.6 (GLIBC_2.6) => /lib/x86_64-linux-gnu/libc.so.6
                libc.so.6 (GLIBC_2.3.3) => /lib/x86_64-linux-gnu/libc.so.6
                libc.so.6 (GLIBC_2.7) => /lib/x86_64-linux-gnu/libc.so.6
                libc.so.6 (GLIBC_2.14) => /lib/x86_64-linux-gnu/libc.so.6
                libc.so.6 (GLIBC_2.3.2) => /lib/x86_64-linux-gnu/libc.so.6
                libc.so.6 (GLIBC_2.3) => /lib/x86_64-linux-gnu/libc.so.6
                libc.so.6 (GLIBC_2.2.5) => /lib/x86_64-linux-gnu/libc.so.6
        /lib/x86_64-linux-gnu/libpthread.so.0:
                ld-linux-x86-64.so.2 (GLIBC_2.2.5) => /lib64/ld-linux-x86-64.so.2
                ld-linux-x86-64.so.2 (GLIBC_PRIVATE) => /lib64/ld-linux-x86-64.so.2
                libc.so.6 (GLIBC_2.14) => /lib/x86_64-linux-gnu/libc.so.6
                libc.so.6 (GLIBC_2.3.2) => /lib/x86_64-linux-gnu/libc.so.6
                libc.so.6 (GLIBC_2.2.5) => /lib/x86_64-linux-gnu/libc.so.6
                libc.so.6 (GLIBC_PRIVATE) => /lib/x86_64-linux-gnu/libc.so.6
        /lib/x86_64-linux-gnu/libm.so.6:
                ld-linux-x86-64.so.2 (GLIBC_PRIVATE) => /lib64/ld-linux-x86-64.so.2
                libc.so.6 (GLIBC_2.2.5) => /lib/x86_64-linux-gnu/libc.so.6
                libc.so.6 (GLIBC_PRIVATE) => /lib/x86_64-linux-gnu/libc.so.6
        /lib/x86_64-linux-gnu/libc.so.6:
                ld-linux-x86-64.so.2 (GLIBC_2.3) => /lib64/ld-linux-x86-64.so.2
                ld-linux-x86-64.so.2 (GLIBC_PRIVATE) => /lib64/ld-linux-x86-64.so.2
```

The only symbols that should be exposed from the binary are the PKCS #11 C\_\*
functions:

```
> nm -gD --defined-only bazel-bin/kmsp11/main/libkmsp11.so
0000000000094f30 T C_CancelFunction
00000000000930b0 T C_CloseAllSessions
0000000000093030 T C_CloseSession
0000000000093480 T C_CopyObject
00000000000933f0 T C_CreateObject
0000000000093be0 T C_Decrypt
0000000000094810 T C_DecryptDigestUpdate
0000000000093d20 T C_DecryptFinal
0000000000093b50 T C_DecryptInit
0000000000093c80 T C_DecryptUpdate
0000000000094950 T C_DecryptVerifyUpdate
0000000000094ce0 T C_DeriveKey
0000000000093520 T C_DestroyObject
0000000000093e30 T C_Digest
0000000000094770 T C_DigestEncryptUpdate
0000000000093fe0 T C_DigestFinal
0000000000093db0 T C_DigestInit
0000000000093f60 T C_DigestKey
0000000000093ed0 T C_DigestUpdate
0000000000093980 T C_Encrypt
0000000000093ac0 T C_EncryptFinal
00000000000938f0 T C_EncryptInit
0000000000093a20 T C_EncryptUpdate
00000000000929a0 T C_Finalize
00000000000937e0 T C_FindObjects
0000000000093870 T C_FindObjectsFinal
0000000000093750 T C_FindObjectsInit
00000000000949f0 T C_GenerateKey
0000000000094a90 T C_GenerateKeyPair
0000000000094e20 T C_GenerateRandom
0000000000093630 T C_GetAttributeValue
0000000000092aa0 T C_GetFunctionList
0000000000094eb0 T C_GetFunctionStatus
0000000000092a20 T C_GetInfo
0000000000092d40 T C_GetMechanismInfo
0000000000092cb0 T C_GetMechanismList
00000000000935a0 T C_GetObjectSize
00000000000931b0 T C_GetOperationState
0000000000093130 T C_GetSessionInfo
0000000000092bb0 T C_GetSlotInfo
0000000000092b20 T C_GetSlotList
0000000000092c30 T C_GetTokenInfo
0000000000092920 T C_Initialize
0000000000092e60 T C_InitPIN
0000000000092dd0 T C_InitToken
00000000000932e0 T C_Login
0000000000093370 T C_Logout
0000000000092f90 T C_OpenSession
0000000000094d90 T C_SeedRandom
00000000000936c0 T C_SetAttributeValue
0000000000093240 T C_SetOperationState
0000000000092ef0 T C_SetPIN
0000000000094100 T C_Sign
00000000000948b0 T C_SignEncryptUpdate
0000000000094230 T C_SignFinal
0000000000094070 T C_SignInit
0000000000094350 T C_SignRecover
00000000000942c0 T C_SignRecoverInit
00000000000941a0 T C_SignUpdate
0000000000094c10 T C_UnwrapKey
0000000000094480 T C_Verify
00000000000945b0 T C_VerifyFinal
00000000000943f0 T C_VerifyInit
00000000000946d0 T C_VerifyRecover
0000000000094640 T C_VerifyRecoverInit
0000000000094520 T C_VerifyUpdate
0000000000094fb0 T C_WaitForSlotEvent
0000000000094b60 T C_WrapKey
0000000000000000 A LIBKMSP11
```

In order to build with a more modern C++ toolchain than the version that ships
with Ubuntu 16.04, we have a custom build toolchain configuration in
//toolchain/llvm\_toolchain.bzl. This
[Bazel C++ toolchain](https://docs.bazel.build/versions/master/tutorial/cc-toolchain-config.html)
can be used with a prebuilt LLVM distribution retrieved from the LLVM project's
[download page](https://releases.llvm.org/download.html).
