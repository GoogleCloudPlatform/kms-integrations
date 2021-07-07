# Using a Cloud HSM key with OpenSSL

## Requirements

This guide provides instructions for setting up OpenSSL to use a Cloud HSM key
on Debian 10 (Buster). You may follow these instructions if you are using
another OS or environment, but be aware that there may be slight differences.

As a prerequisite, we need to install the `libengine-pkcs11-openssl` package.

```sh
sudo apt-get update
sudo apt-get install libengine-pkcs11-openssl
```

## Configuration

### Setting the PKCS11_MODULE_PATH environment variable.

In order for `openssl` to use our PKCS #11 library, we need to set the
`PKCS11_MODULE_PATH` environment variable:

```sh
export PKCS11_MODULE_PATH="/path/to/libkmsp11.so"
```

You can make this permanent by adding that line to /etc/profile.

```sh
echo 'export PKCS11_MODULE_PATH="/path/to/libkmsp11.so"' | sudo tee /etc/profile
```

### PKCS #11 Library Configuration

The library requires a YAML configuration file in order to locate Cloud KMS
resources. The YAML must at a minimum configure a single PKCS #11 token.

If you are using OpenSSL with another process that may end up forking (for
example, Apache or Nginx), you must also ensure that the
`refresh_interval_secs` field remains unset, or is set to 0.

Sample configuration file:

```yaml
---
tokens:
  - key_ring: "projects/my-project/locations/us-central1/keyRings/my-keyring"
```

With this configuration, all asymmetric signing and decryption keys in
`my-keyring` will be available in the library.

You must set the permissions on the configuration file so that it is writable
only by the file owner. Point `KMS_PKCS11_CONFIG` to your config file:

```
export KMS_PKCS11_CONFIG="/path/to/pkcs11-config.yaml"
```

Again, you can make this permanent by adding that line to /etc/profile.

```sh
echo 'export KMS_PKCS11_CONFIG="/path/to/pkcs11-config.yaml"' | sudo tee /etc/profile
```

## Running OpenSSL commands

With the engine and library properly configured, you may now use the engine in
OpenSSL commands.

Note when creating asymmetric signatures that Cloud KMS keys are constrained
to use a single digest. As an example, a CryptoKeyVersion with the algorithm
`EC_SIGN_P256_SHA256` must always be used in conjunction with a SHA-256 digest.
That would correspond to the `-sha256` flag in OpenSSL. Keys that require
SHA-384 or SHA-512 digests should be used with the `-sha384` or `-sha512` flags.

Note when creating asymmetric signatures using Cloud KMS keys with an algorithm
starting with `RSA_PSS` that additional options are typically required by
OpenSSL: `-sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest`.

### Example: Creating a new signature

Assuming a key named `foo` in your configured key ring, you could create a
signature over `bar.txt` using the following command:

```sh
openssl dgst -sha256 -engine pkcs11 -keyform engine -sign pkcs11:object=foo bar.txt
```

Note that the output will be unformatted binary.

That command assumes we're using a key that takes a SHA-256 digest, so the
`-sha256` argument was used. The `-sha384` or `-sha512` options would be
appropriate for Cloud HSM keys that use those digest types.

For an RSA-PSS key, remember to use the `-sigopt` options discussed previously.

### Example: Creating a new certificate signing request

You may also generate a certificate signing request (CSR) for a Cloud HSM
signing key. This is useful if your certificate authority requires a CSR in
order to generate a new certificate for code signing, or to protect TLS web
sessions.

```
openssl req -new -subj '/CN=test/' -sha256 -engine pkcs11 \
  -keyform engine -key pkcs11:object=foo > my-request.csr
```

Note: you may only create CSRs for Cloud KMS CryptoKeys with the
`ASYMMETRIC_SIGN` purpose. In addition, take care to use the right digest
algorithm and `-sigopt` options for the key type.

### Example: Generating a new self-signed certificate

You may also generate a self-signed certificate for a Cloud HSM signing key.
This is useful if you are using the key for SAML token signing, or for
local development and testing.

```
openssl req -new -x509 -days 3650 -subj '/CN=test/' -sha256 -engine pkcs11 \
  -keyform engine -key pkcs11:object=foo > my-request.crt
```

Note: you may only create self-signed certificates for Cloud KMS CryptoKeys
with the `ASYMMETRIC_SIGN` purpose. In addition, take care to use the right
digest algorithm and `-sigopt` options for the key type.
