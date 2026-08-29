# Public Key Generator

`docker build -t extractpubkey .`

Put signing keys in a file named `signing-keys.txt` in CSV format `issuer_id,signing_key` with no header. Then run:

```
docker run -it -v "$(pwd):/data" extractpubkey:latest /bin/main /data/signing-keys.txt
```

The result will be output with the public key in the format `id, signing key, public key`.
