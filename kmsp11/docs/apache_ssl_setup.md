# Using a Cloud HSM key to serve Apache traffic

## Requirements

This guide provides instructions for setting up an Apache server to use a Cloud
HSM key for TLS signing on Debian 10 (Buster). You may follow these instructions
if you are using another OS or environment, but be aware that there may be
slight differences.

We need the `apache2` and `libengine-pkcs11-openssl` packages. Note that
PKCS #11 URIs are only available in `apache2-2.4.42` and later, so you will need
to enable backports and select that as the source for the `apache2` package.

```
# Add backports to your sources
echo deb http://deb.debian.org/debian buster-backports main | sudo tee /etc/apt/sources.list.d/buster-backports.list

sudo apt-get update
sudo apt-get install libengine-pkcs11-openssl
sudo apt-get install -t buster-backports apache2
```

> TIP: PKCS #11 URIs are only available in `apache2-2.4.42` and later.
>
> You might need to upgrade your previously installed `apache2` package with the
> command above, or install from non-stable sources. For Debian instances: `sudo
> apt install -t buster-backports apache2`

## Downloading the latest PKCS #11 Cloud KMS Library version

> TODO(b/175421728): Add non-internal build download link.

The latest linux amd64 release build can be downloaded < here >.

In order for `openssl` to use our PKCS #11 library, we need to set the
`PKCS11_MODULE_PATH` environment variable:

```
export PKCS11_MODULE_PATH="/path/to/libkmsp11.so"
```

## Configuration

### Creating a KMS-hosted signing key

Create a Cloud KMS EC-P256-SHA256 signing key in your GCP project:

```
# Create a fresh keyring
gcloud kms keyrings create "apache-keyring" --project "your-project-name" --location "us-central1"

# Create a new HSM-backed EC-P256-SHA256 signing key
gcloud kms keys create "apache-key" --keyring "apache-keyring" --project "project-name" --location "us-central1" \
  --purpose "asymmetric-signing" --default-algorithm "ec_sign_p256_sha256" --protection-level "hsm"
```

NOTE: Make sure that your GCE service account has the right IAM permissions on
the keyring to be able to use it. If you are not using a GCE VM, see the service
account (instructions)[https://cloud.google.com/docs/authentication/production].

### PKCS #11 Cloud KMS Library Configuration

The library requires a YAML configuration file in order to locate Cloud KMS
resources. The YAML must at a minimum configure a single PKCS #11 token, and
ensure that the `refresh_interval_secs` field is set to 0.

Sample configuration file:

```yaml
---
tokens:
  - key_ring: "projects/my-project/locations/us-central1/keyRings/apache-keyring"
log_directory: "/var/log/kmsp11"
refresh_interval_secs: 0
```

You must set the permissions on the configuration file so that it is writable
only by the file owner. Point `KMS_PKCS11_CONFIG` to your config file:

```
export KMS_PKCS11_CONFIG="/path/to/pkcs11-config.yaml"
```

### Creating a self-signed certificate with OpenSSL

Generate a self-signed certificate with the KMS-hosted signing key. To do so,
OpenSSL allows you to use PKCS #11 URIs instead of a regular file path,
identifying the key by its label (for KMS keys, that is equivalent to the
CryptoKey name).

```
openssl req -new -x509 -days 3650 -subj '/CN=test/' -sha256 -engine pkcs11 \
  -keyform engine -key pkcs11:object=apache-key > ca.cert
```

If the above command fails, `PKCS11_MODULE_PATH` may have been set incorrectly,
or you might not have the right permissions to use the KMS signing key. You
should now have a certificate that looks like this:

```
-----BEGIN CERTIFICATE-----
...
...
...
-----END CERTIFICATE-----
```

## Setting up the Apache server

First, create a directory in `/etc/apache2` to store your self-signed
certificate in:

```
sudo mkdir /etc/apache2/ssl
sudo mv ca.cert /etc/apache2/ssl
```

You can then edit the `000-default.conf` virtual host configuration files
located in `/etc/apache2/sites-available` to provide the certificate file path
and ensure that the SSLEngine is on.

<section class="zippy">

Sample configuration, listening on port 443:

```
  <VirtualHost *:443>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
        SSLEngine on
        SSLCertificateFile /etc/apache2/ssl/ca.cert
        SSLCertificateKeyFile "pkcs11:object=apache-key"
  </VirtualHost>
```

</section>

We also need to make sure Apache exports our environment variables correctly by
adding them to the `/etc/apache2/envvars` file:

```
sudo vi /etc/apache2/envvars

# Add the following lines:
export PKCS11_MODULE_PATH="/path/to/libkmsp11.so"
export KMS_PKCS11_CONFIG="/path/to/pkcs11-config.yaml"
export GRPC_ENABLE_FORK_SUPPORT=1
```

`GRPC_ENABLE_FORK_SUPPORT`, as you might have guessed, is needed for gRPC to
include fork support and correctly run the KMS PKCS #11 library as part of the
Apache server.

### Running your server

Enable the Apache SSL module, enable the virtualhost configuration, and add a
test webpage in your DocumentRoot folder:

```
a2enmod ssl
a2ensite 000-default.conf
echo '<!doctype html><html><body><h1>Hello World!</h1></body></html>' | sudo tee /var/www/html/index.html
```

Restart your Apache server and test with `curl` that the configuration works as
expected:

```
sudo systemctl restart apache2
curl -vk https://127.0.0.1
```

If you encounter any errors, the Apache error log is probably a good starting
place to see what went wrong.

