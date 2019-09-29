# FileLock
Encrypts/decrypts user specified files with a password. (In Progress)

# Choice of Language
I was going to use Crypto++ but then I could have also gone with Python, whole reason to use C++ was to use pointers and array and work at a lower level to implement AES. Although, it seems like I might use golang to handle main calling; For now this is going to be a C++ only project.

# AES Implementation
My knowledge of AES is a mix from wikipedia, "Introduction to Cryptography by Christof Paar" lecture series and his corresponding book "Understanding Cryptography". This should explain some of naming I used inside the implementation as learned from lecture series but while implementing jumped into wikipedia and book.

For testing I used Test vectors in original paper for key schedule:

>>"Advanced Encryption Standard (AES)" (PDF). Federal Information Processing Standards. 26 November 2001. doi:10.6028/NIST.FIPS.197.

Everything else was tested by test vectors on wikipedia pages.

# Status and Scope
The project will be able to
* Lock directories (locking individual things in it)
* Use SHA hashes to convert password to keys for encryption.
* Encrypt multiple files using threading/async algorithms.

Right now I am implementing AES. I will try to fast forward after this and use go/Python to fulfill other features and then slowly replace them. I feel this works best in a project.

