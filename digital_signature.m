clc; clear; close all;

%% Step 1: Select a file
filePath = 'A-Novel-Approach-for-Ticket-Generation-and-Validation-Using-RSA-and-Keccak-Algorithms.pdf';   % <--- replace with your file
fprintf('==============================\n');
fprintf(' STEP 1: FILE SELECTION\n');
fprintf('==============================\n');
fprintf('Selected File: %s\n\n', filePath);

fid = fopen(filePath, 'rb');
fileData = fread(fid);
fclose(fid);

%% Step 2: Compute SHA-512 hash
fprintf('==============================\n');
fprintf(' STEP 2: HASHING (SHA-512)\n');
fprintf('==============================\n');
md = java.security.MessageDigest.getInstance('SHA-512');
md.update(uint8(fileData));
hashBytes = md.digest();

% Convert hash to hex string
hash_hex = dec2hex(typecast(hashBytes,'uint8'))';
hash_str = lower(reshape(hash_hex,1,[]));
fprintf('SHA-512 Hash of file:\n%s\n\n', hash_str);

% Convert to BigInteger
hash_val = java.math.BigInteger(1, hashBytes);

%% Step 3: RSA Key Generation
fprintf('==============================\n');
fprintf(' STEP 3: RSA KEY GENERATION\n');
fprintf('==============================\n');

% Generate large primes (512-bit each)
bitLength = 512;
p = java.math.BigInteger.probablePrime(bitLength, java.util.Random);
q = java.math.BigInteger.probablePrime(bitLength, java.util.Random);

n = p.multiply(q);                        % Modulus
p_minus_1 = p.subtract(java.math.BigInteger.ONE);
q_minus_1 = q.subtract(java.math.BigInteger.ONE);
phi_n = p_minus_1.multiply(q_minus_1);

% Choose public exponent e
e = java.math.BigInteger.valueOf(65537);  % Commonly used

% Compute private exponent d
d = e.modInverse(phi_n);

fprintf('Prime p:\n%s\n\n', char(p.toString(16)));
fprintf('Prime q:\n%s\n\n', char(q.toString(16)));
fprintf('Modulus n (p*q):\n%s\n\n', char(n.toString(16)));
fprintf('Public Exponent e: %s\n\n', char(e.toString(10)));
fprintf('Private Exponent d:\n%s\n\n', char(d.toString(16)));

fprintf('Public Key (e,n) generated.\n');
fprintf('Private Key (d,n) generated.\n\n');

%% Step 4: Signature Generation
fprintf('==============================\n');
fprintf(' STEP 4: SIGNATURE GENERATION\n');
fprintf('==============================\n');
signature = hash_val.modPow(d, n);
fprintf('Digital Signature (hex):\n%s\n\n', char(signature.toString(16)));

%% Step 5: Signature Verification
fprintf('==============================\n');
fprintf(' STEP 5: SIGNATURE VERIFICATION\n');
fprintf('==============================\n');

% Decrypt signature with public key
decrypted_hash = signature.modPow(e, n);

fprintf('Decrypted Hash from Signature (hex):\n%s\n\n', char(decrypted_hash.toString(16)));
fprintf('Original Hash (hex):\n%s\n\n', hash_str);

% Compare
if decrypted_hash.equals(hash_val)
    fprintf(' Signature Verified: File is Authentic & Untampered.\n');
else
    fprintf(' Signature Verification Failed: File may be Tampered.\n');
end
