# CryptUtils

`CryptUtils` is a Python package for encryption and decryption including SM2, SM4.

## SM2/SM4 Encrypt and Decrypt

```
from CryptUtils import SM2Encrypt, SM2Decrypt, SM4Encrypt, SM4Decrypt

SM2Encrypt(data)
SM2Decrypt(cipher)
SM4Encrypt(data, key, gzip = false)
SM4Decrypt(cipher, key, gzip = false)
```

## Arguments

- `data`: The data to be encrypted.
- `cipher`: The encrypted data to be decrypted.
- `key`: The key used for SM4 encryption and decryption.
- `gzip`: A boolean flag indicating whether to use gzip compression (default is false).
