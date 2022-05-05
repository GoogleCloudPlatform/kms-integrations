# Release Notes

## PKCS #11 Cloud KMS Library

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
