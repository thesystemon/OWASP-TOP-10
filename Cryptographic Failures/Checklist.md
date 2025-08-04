### ✅ **Cryptographic Failures Checklist (Offensive Security Focused)**

#### 🔐 **1. TLS/SSL Misconfigurations**

* [ ] Is the application using outdated or vulnerable protocols (e.g., SSL 2.0, SSL 3.0, TLS 1.0/1.1)?
* [ ] Are weak ciphers or cipher suites like RC4, DES, or 3DES in use?
* [ ] Is there lack of Perfect Forward Secrecy (PFS)?
* [ ] Is the certificate self-signed or expired?
* [ ] Does the server support insecure renegotiation?
* [ ] Is HSTS (HTTP Strict Transport Security) missing?

#### 🔑 **2. Insecure Storage or Transmission of Sensitive Data**

* [ ] Is sensitive data (e.g., passwords, credit card info) being transmitted over plain HTTP?
* [ ] Is sensitive data being stored without encryption at rest?
* [ ] Are hardcoded encryption keys or credentials found in code?
* [ ] Is sensitive data being cached, logged, or stored in URL parameters?

#### 🧪 **3. Weak Encryption Algorithms**

* [ ] Are deprecated algorithms like MD5, SHA-1, RC4 used?
* [ ] Is ECB mode used in block ciphers instead of CBC/GCM?
* [ ] Are weak or predictable IVs and nonces being used?
* [ ] Is custom or homegrown encryption implemented?

#### 🔄 **4. Key Management Failures**

* [ ] Are encryption keys stored in code or config files?
* [ ] Is there no key rotation mechanism in place?
* [ ] Are the same keys used across multiple environments (dev, prod)?
* [ ] Is the key length insufficient (e.g., AES-128 when AES-256 is feasible)?

#### 🧍 **5. Improper Password Hashing**

* [ ] Are passwords stored using unsalted hashes?
* [ ] Is a fast hashing algorithm (e.g., MD5, SHA1, SHA256) used instead of bcrypt, Argon2, or PBKDF2?
* [ ] Is a static salt or no salt used at all?
* [ ] Is password stretching missing?

#### 🔓 **6. Missing or Weak Authentication Tokens**

* [ ] Are JWTs signed with none algorithm or symmetric key exposed?
* [ ] Is there lack of token expiration or rotation?
* [ ] Are tokens stored in insecure places (e.g., localStorage)?

#### 📡 **7. Lack of Cryptographic Verification**

* [ ] Is digital signature verification missing or improperly implemented?
* [ ] Is the integrity of downloaded files/packages unverified (e.g., no checksums)?

#### 🏗️ **8. Insecure Random Number Generation**

* [ ] Is `rand()` or insecure PRNG used instead of `cryptographically secure PRNG`?
* [ ] Are predictable or sequential token values observed?

#### 🚫 **9. Broken or Missing Encryption**

* [ ] Is encryption advertised but not actually implemented?
* [ ] Is there sensitive data leaking via side channels (e.g., timing, error messages)?
* [ ] Are backups encrypted?

#### 📋 **10. Server & Infrastructure Configuration**

* [ ] Is there a weak SSH configuration (e.g., outdated ciphers)?
* [ ] Are credentials and private keys exposed via Git history or open directories?
* [ ] Is TLS not enforced via redirection or HSTS headers?

---
