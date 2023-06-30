# Release Notes

## Table of Contents

1.  [PKCS#11 Library](#pkcs-11-cloud-kms-library)
2.  [CNG Provider](#cng-provider-for-cloud-kms)

## PKCS #11 Cloud KMS Library

### v1.2

The following changes are included in the v1.2 (April 2023) release:

*   Add support for digesting mechanisms that can sign over raw data instead of
    precomputed digests. See [mechanism.cc][mechanisms] for the full list.
*   Add support for multi-part signing functions (`C_{Sign|Verify}Update`, and
    `C_{Sign|Verify}Final`). See the [user guide][user-guide] for more details
    about these functions.
*   Add support for `C_GenerateRandom`, see the [user guide][user-guide] for
    more details.
*   Add experimental support for interoperable AES symmetric encryption
    mechanisms, such as `CKM_AES_CTR`, and the related functions (eg.
    `C_Encrypt`, `C_Decrypt`, etc). See the [user guide][user-guide] for the
    full list of mechanisms and functions. This feature is currently in private
    preview and can only be accessed by allowlisted preview customers. If
    you are interested, please fill out
    [this form](https://forms.gle/z8qpV5wkG9gtVCof8).
*   Add experimental support for HMAC symmetric signing mechanisms, such as
    `CKM_SHA256_HMAC`. Some of these algorithms are in public preview but can
    be accessed without restrictions. See [mechanism.cc][mechanisms] for the full
    list of mechanisms.
*   Add integrity verification checks for crypto operations performed through
    the library.
*   Support case #1 of
    [`C_Initialize`](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc385057894)
*   Several internal dependencies were updated.

### v1.1

The following changes are included in the v1.1 (March 2022) release:

*   The value for `CKA_EC_POINT` was corrected.
*   The configuration option `experimental_generate_certs` is now fully
    supported, and has been renamed to `generate_certs`.
*   Google now supplies a version of the library where the included BoringSSL
    has been built in FIPS mode.
*   The configuration option `experimental_require_fips_mode` is now fully
    supported, and has been renamed to `require_fips_mode`.
*   For `CK_RSA_PKCS_OAEP_PARAMS.source`, the value `0` is treated as
    meaning "no label" for compatibility purposes.
*   The library must now be built with Bazel v4.2.1.
*   Several internal dependencies were updated.

### v1.0

Initial release of the library.

## CNG Provider for Cloud KMS

### v0.8

Initial release of the library.


[mechanisms]: kmsp11/mechanism.cc
[user-guide]: kmsp11/docs/user_guide.md
