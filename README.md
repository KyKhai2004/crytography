# crypto_usth

# overview
Algorithm used:
- Symmetric encryption (AES) for message confidentiality.
- Asymmetric encryption (RSA) for securely exchanging the symmetric key.
- Digital signatures (RSA) for authenticity and integrity.

# Flow  
- Generated AES key to encrypt the message
- The sender signs the plaintext message, using their private RSA key to create a signature.
- Use AES key to encrypt the message
- The sender encrypts the AES key using the receiver’s public RSA key.
- The sender send the cipher text, encrypted AES key and the signature
- The receivers decrypt the AES key using their private RSA key.
- Use AES key to and decrypt the message
- The receiver verifies the signature using the sender’s public RSA key, the decrypted message, and the received signature.

# run demo
run main.py

# function.py
- include necessary function

# pack
(testing...)
# test dir
test the flow
- $python key_generate.py
- $python test_rsa_signature.py

# run bench
- file benchmark sẽ chứa những hàm để đo lường các thông số
- file run_bench mình sẽ import các hàm từ benchmark vào để chạy rồi xuất tất cả kết quả đo lường ra một file là benchmark_result.csv
- Ngoài ra ta có thể điều chỉnh scability thông qua câu lệnh
```python run_bench.py --group-size 100``` chúng ta có thể điều chỉnh group size tùy ý để thấy sự khác biệt
