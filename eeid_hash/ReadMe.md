# Verifying that an EE-ID is currently valid

```bash
nargo execute

bb write_vk -b ./target/eeid.json -o target

bb prove -b ./target/eeid.json -w ./target/eeid.gz -o target

bb verify -p ./target/proof -k ./target/vk -i ./target/public_inputs
```

