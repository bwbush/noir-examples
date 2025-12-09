# Extracting certificate, public key, and signature for EE ID examples


## Extract the certificate body and its signature.

```bash
# Extract the signing certificate from the EE ID smartcard.
pkcs15-tool --read-certificate 02 > ee-id-2.cer

# View the details of the certificate.
openssl asn1parse -in ee-id-2.cer -inform pem -dump

# Extract the body.
openssl asn1parse -in ee-id-2.cer -inform pem -strparse 4 -out tbs.der

# Compute the hash of the body.
openssl dgst -sha512 -binary tbs.der > m.bin

# Extract the signature.
openssl asn1parse -in ee-id-2.cer -inform pem -strparse $((838 + 3 + 1)) -out sig.der

# Extract r.
dd if=sig.der bs=1 skip=$((3+2)) count=66 of=r.bin
xxd -p -c0 r.bin | tee r.hex

# Extract s.
dd if=sig.der bs=1 skip=$((71+2)) count=66 of=s.bin
xxd -p -c0 s.bin | tee s.hex
```

## Extract the public key of the intermediate CA.

```bash
# Fetch the CA certificates.
wget https://c.sk.ee/EE-GovCA2018.der.crt
wget https://c.sk.ee/esteid2018.der.crt

# Extract the public key of the intermediate.
openssl x509 -inform der -in esteid2018.der.crt -pubkey -noout > inter_pub.pem
openssl pkey -pubin -inform pem -in inter_pub.pem -outform der -out inter_pub.der

# View the public key.
openssl asn1parse -in inter_pub.der -inform der -i -dump

# Extract x.
dd if=inter_pub.der bs=1 count=66 skip=$((21+3+2)) count=66 of=x.bin
xxd -p -c0 x.bin | tee x.hex

# Extract y.
dd if=inter_pub.der bs=1 count=66 skip=$((21+3+2+66)) count=66 of=y.bin
xxd -p -c0 y.bin | tee y.hex
```
