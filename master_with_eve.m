function master_rsa_dh_aes_demo_with_eve()
% MASTER_RSA_DH_AES_DEMO_WITH_EVE
% Modified demo: adds an "Eve" attacker that can tamper with:
%   - the encrypted transport blob (IV||ciphertext)
%   - the ASCII-hex RSA signature
%   - or both
%
% Set enableEve = true to simulate the attacker; choose eveMode: 'file','signature','both','none'
%
% Other behavior remains the same as your original demo.

clc; clear; close all;
fprintf('====================================================================\n');
fprintf(' MASTER DEMO (WITH EVE ATTACKER OPTION): Diffie-Hellman + AES-CBC + RSA sig\n');
fprintf('====================================================================\n\n');

%% ---------------- Config ----------------
% Files
inputFile  = 'Crypto_Case_Study_Final.pdf';    % file to encrypt & sign
encFileOut = 'Encrypted.bin';                  % stored transport file (IV||ciphertext)
decFileOut = 'Decrypted.pdf';                  % decrypted output

% Security / size parameters (demo)
dhBitLength    = 512;    % DH prime bits (use 2048+ in production)
rsaPrimeBits   = 512;    % RSA prime bits for p and q (use 2048+ in production)

% Channel simulation probabilities (0 = ideal)
channelErrorProb_publicKeys = 0.0;   % for A and B exchange
channelErrorProb_file       = 0.0;   % for encrypted file transfer (regular channel errors)
channelErrorProb_signature  = 0.0;   % for signature transfer (regular channel errors)

% ---------------- Eve attacker config ----------------
enableEve = true;                 % set to true to enable Eve
% modes: 'file' (tamper encrypted blob), 'signature' (tamper ASCII-hex signature),
% 'both' (tamper both), 'none' (no attacker)
eveMode = 'file';                 % choose 'file','signature','both','none'
eveFlipBytes = 5;                 % how many random bytes Eve flips in transport blob when tampering
eveSigFlipNibbles = 3;            % how many hex nibbles Eve flips in signature ASCII when tampering

fprintf('Configuration:\n');
fprintf('  DH bits = %d, RSA prime bits = %d\n', dhBitLength, rsaPrimeBits);
fprintf('  Channel error probs: publicKeys=%.3f, file=%.3f, signature=%.3f\n', ...
    channelErrorProb_publicKeys, channelErrorProb_file, channelErrorProb_signature);
fprintf('  Eve enabled = %d, mode = %s, eveFlipBytes=%d, eveSigFlipNibbles=%d\n\n', ...
    enableEve, eveMode, eveFlipBytes, eveSigFlipNibbles);

%% ---------------- Diffie-Hellman key exchange ----------------
fprintf('--- DIFFIE-HELLMAN KEY EXCHANGE (Alice <-> Bob) ---\n\n');

import java.math.BigInteger;
import java.util.Random;

randObj = Random();

% 1) Generate large prime p
fprintf('STEP DH-1: Generating large prime modulus p (%d bits)...\n', dhBitLength);
pBig = BigInteger.probablePrime(int32(dhBitLength), randObj);
pStr = char(pBig.toString(10));   % decimal string
fprintf('  p (decimal, truncated) = %s...\n\n', pStr(1:min(200,numel(pStr))));

% 2) Choose generator g
g = 5;  % fixed generator (ok for demo)
fprintf('STEP DH-2: Generator g chosen = %d\n\n', g);

% 3) Alice generates private a and public A
aBig = BigInteger(int32(dhBitLength-2), randObj).mod(pBig.subtract(BigInteger.valueOf(3))).add(BigInteger.valueOf(2));
A_Big = BigInteger.valueOf(g).modPow(aBig, pBig);
aStr = char(aBig.toString(10));
A_str = char(A_Big.toString(10));
fprintf('STEP DH-3: Alice generated keys.\n');
fprintf('  Alice private a (decimal, truncated) = %s...\n', aStr(1:min(120,numel(aStr))));
fprintf('  Alice public  A (decimal, truncated) = %s...\n\n', A_str(1:min(120,numel(A_str))));

% 4) Bob generates private b and public B
bBig = BigInteger(int32(dhBitLength-2), randObj).mod(pBig.subtract(BigInteger.valueOf(3))).add(BigInteger.valueOf(2));
B_Big = BigInteger.valueOf(g).modPow(bBig, pBig);
bStr = char(bBig.toString(10));
B_str = char(B_Big.toString(10));
fprintf('STEP DH-4: Bob generated keys.\n');
fprintf('  Bob private b (decimal, truncated) = %s...\n', bStr(1:min(120,numel(bStr))));
fprintf('  Bob public  B (decimal, truncated) = %s...\n\n', B_str(1:min(120,numel(B_str))));

% 4.5) Simulated Channel: exchange A and B (with optional bit flips)
fprintf('STEP DH-4.5: Simulating public channel for A & B exchange (error prob = %.3f)...\n', channelErrorProb_publicKeys);
A_bytes = uint8(A_str);  % ASCII decimal
B_bytes = uint8(B_str);
A_bytes_rx = simulate_channel(A_bytes, channelErrorProb_publicKeys);
B_bytes_rx = simulate_channel(B_bytes, channelErrorProb_publicKeys);

% Reconstruct BigInteger from received ASCII decimal strings
try
    A_Big_rx = BigInteger(char(A_bytes_rx), 10);
    B_Big_rx = BigInteger(char(B_bytes_rx), 10);
catch
    error('Channel corrupted ASCII numeric digits for A/B — reconstruction failed. Reduce channel error prob.');
end
A_rx_str = char(A_Big_rx.toString(10));
B_rx_str = char(B_Big_rx.toString(10));
fprintf('  Alice sent A, Bob received (truncated) = %s...\n', A_rx_str(1:min(120,numel(A_rx_str))));
fprintf('  Bob sent B, Alice received (truncated) = %s...\n\n', B_rx_str(1:min(120,numel(B_rx_str))));

% 5) Each computes shared secret using received public value
AliceSharedBig = B_Big_rx.modPow(aBig, pBig);   % S = B_received^a mod p
BobSharedBig   = A_Big_rx.modPow(bBig, pBig);   % S = A_received^b mod p

if ~AliceSharedBig.equals(BobSharedBig)
    error('DH shared secrets do NOT match -> possible channel corruption during A/B exchange.');
end
sharedSecretStr = char(AliceSharedBig.toString(10));
fprintf('STEP DH-5: Shared secret S computed by both parties (truncated):\n%s...\n\n', sharedSecretStr(1:min(200,numel(sharedSecretStr))));

% 6) Derive AES-256 key from shared secret via SHA-256
md = java.security.MessageDigest.getInstance('SHA-256');
digest_shared_java = md.digest(AliceSharedBig.toByteArray());   % Java byte[]
aesKey = typecast(int8ToUint8Array(digest_shared_java), 'uint8');  % 32 bytes
fprintf('STEP DH-6: Derived AES-256 key via SHA-256(sharedSecret).\n');
disp('AES key (hex, 32 bytes):'); disp(dec2hex(aesKey)'); fprintf('\n');

%% ---------------- AES-CBC ENCRYPTION of PDF (Alice) ----------------
fprintf('--- AES-CBC ENCRYPTION (Alice) ---\n\n');

% Check input file exists
if ~isfile(inputFile)
    error('Input file "%s" not found in current folder. Place the PDF and re-run.', inputFile);
end

% Read file bytes
fid = fopen(inputFile, 'rb'); fileBytes = fread(fid, Inf, '*uint8'); fclose(fid);
fprintf('STEP ENC-1: Read input file "%s" (%d bytes).\n\n', inputFile, numel(fileBytes));

% Generate random IV (16 bytes)
iv = uint8(randi([0 255], 1, 16));
fprintf('STEP ENC-2: Generated random IV for AES-CBC (16 bytes):\n'); disp(dec2hex(iv)); fprintf('\n');

% Encrypt file bytes with derived AES key
ciphertext = aes_encrypt_bytes(fileBytes, aesKey, iv);
fprintf('STEP ENC-3: Performed AES-CBC encryption.\n  Ciphertext length (bytes) = %d\n\n', numel(ciphertext));

% Create transport blob: [IV || ciphertext]
ivRow = reshape(iv, 1, []);
cipherRow = reshape(ciphertext, 1, []);
transportBlob = [ivRow cipherRow];

% Save original encrypted file locally (before simulated channel)
fid = fopen(encFileOut, 'wb'); fwrite(fid, transportBlob, 'uint8'); fclose(fid);
fprintf('STEP ENC-4: Saved local encrypted blob as "%s" (contains IV||ciphertext).\n\n', encFileOut);

%% -------------- Create SHA-512 hash of ORIGINAL file (for signature) -------------
fprintf('--- SIGNING (SHA-512 of file) ---\n\n');
md512 = java.security.MessageDigest.getInstance('SHA-512');
md512.update(int8(fileBytes));
hash512_java = md512.digest();                       % Java byte[]
hashBytes = typecast(int8ToUint8Array(hash512_java),'uint8');  % MATLAB uint8
hash_hex = lower(reshape(dec2hex(hashBytes)',1,[]));
fprintf('STEP SIG-1: SHA-512 hash of original file (hex, truncated):\n%s\n\n', hash_hex(1:min(200,numel(hash_hex))));

% Convert hash to BigInteger (positive)
hash_val = java.math.BigInteger(1, int8ToUint8Array(hash512_java));

%% ---------------- RSA KEY GENERATION (for signing) ----------------
fprintf('--- RSA KEY GENERATION (for digital signature) ---\n\n');
p_rsa = java.math.BigInteger.probablePrime(int32(rsaPrimeBits), randObj);
q_rsa = java.math.BigInteger.probablePrime(int32(rsaPrimeBits), randObj);
n_rsa = p_rsa.multiply(q_rsa);
phi_n = p_rsa.subtract(java.math.BigInteger.ONE).multiply(q_rsa.subtract(java.math.BigInteger.ONE));

% Choose public exponent e (65537)
e_rsa = java.math.BigInteger.valueOf(65537);
d_rsa = e_rsa.modInverse(phi_n);   % private exponent

n_rsa_hex = char(n_rsa.toString(16));
d_rsa_hex = char(d_rsa.toString(16));
fprintf('STEP RSA-1: RSA key pair generated.\n');
fprintf('  RSA modulus n (hex, truncated) = %s...\n', n_rsa_hex(1:min(200,numel(n_rsa_hex))));
fprintf('  Public exponent e = %s\n', char(e_rsa.toString(10)));
fprintf('  Private exponent d (hex, truncated) = %s...\n\n', d_rsa_hex(1:min(120,numel(d_rsa_hex))));

%% --------------- Signature generation (Alice) -----------------
fprintf('--- SIGNATURE GENERATION (Alice) ---\n\n');
signatureBig = hash_val.modPow(d_rsa, n_rsa);    % signature = hash^d mod n
sig_hex = char(signatureBig.toString(16));
fprintf('STEP SIG-2: Digital signature (hex, truncated):\n%s...\n\n', sig_hex(1:min(200,numel(sig_hex))));

%% --------------- Simulate transmission of encrypted blob & signature ---------------
fprintf('--- TRANSMISSION (Simulated channel) ---\n\n');

% 1) Simulate sending public transportBlob (IV||ciphertext) to Bob
fprintf('Transmitting encrypted blob (IV||ciphertext) with channel error prob = %.3f\n', channelErrorProb_file);
transportBlob_rx = simulate_channel(transportBlob, channelErrorProb_file);

% Save received blob (for demonstration)
fid = fopen(['received_' encFileOut],'wb'); fwrite(fid, transportBlob_rx, 'uint8'); fclose(fid);

% 2) Simulate sending signature (as hex ASCII) to Bob
sig_ascii = uint8(sig_hex);   % ASCII hex representation
fprintf('Transmitting signature (ASCII hex) with channel error prob = %.3f\n', channelErrorProb_signature);
sig_ascii_rx = simulate_channel(sig_ascii, channelErrorProb_signature);

% ---------- EVE ATTACKER (optional) ----------
if enableEve
    fprintf('--- EVE ATTACKER ACTIVE: mode = %s ---\n', eveMode);
    switch lower(eveMode)
        case 'file'
            transportBlob_rx = eve_attack_transport_blob(transportBlob_rx, eveFlipBytes);
            fprintf('Eve tampered with the encrypted blob (flipped %d bytes).\n', eveFlipBytes);
        case 'signature'
            sig_ascii_rx = eve_attack_signature_ascii(sig_ascii_rx, eveSigFlipNibbles);
            fprintf('Eve tampered with the signature ASCII (flipped %d hex nibbles).\n', eveSigFlipNibbles);
        case 'both'
            transportBlob_rx = eve_attack_transport_blob(transportBlob_rx, eveFlipBytes);
            sig_ascii_rx = eve_attack_signature_ascii(sig_ascii_rx, eveSigFlipNibbles);
            fprintf('Eve tampered with both blob and signature (bytes=%d, nibbles=%d).\n', eveFlipBytes, eveSigFlipNibbles);
        otherwise
            fprintf('Eve mode "%s" not recognized — no attack performed.\n', eveMode);
    end
else
    fprintf('Eve disabled -> normal transmission.\n');
end
fprintf('\n');

% Reconstruct signature BigInteger at receiver side from ASCII hex
try
    signatureBig_rx = java.math.BigInteger(char(sig_ascii_rx), 16);
catch
    error('Signature transmission corrupted into non-hex ASCII. Reduce channel error prob or change Eve settings.');
end

fprintf('Transmission complete. Received encrypted blob length = %d bytes.\n', numel(transportBlob_rx));
sig_rx_str = char(signatureBig_rx.toString(16));
fprintf('Received signature (hex, truncated): %s...\n\n', sig_rx_str(1:min(150,numel(sig_rx_str))));

%% ---------------- Receiver (Bob) side: Decrypt & Verify ----------------
fprintf('--- RECEIVER (Bob) PROCESSING ---\n\n');

% Extract IV and ciphertext from received blob
if numel(transportBlob_rx) < 17
    error('Received blob too small to contain IV + ciphertext.');
end
iv_received = transportBlob_rx(1:16);
cipher_received = transportBlob_rx(17:end);
fprintf('STEP REC-1: Extracted IV (16 bytes) and ciphertext (len=%d bytes).\n', numel(cipher_received));
disp('Received IV (hex):'); disp(dec2hex(iv_received)); fprintf('\n');

% Attempt to decrypt using derived AES key
try
    plain_received = aes_decrypt_bytes(cipher_received, aesKey, iv_received);
    fprintf('STEP REC-2: AES-CBC decryption successful. Decrypted length = %d bytes.\n\n', numel(plain_received));
catch ME
    fprintf('ERROR during AES decryption: %s\n', ME.message);
    error('Decryption failed — possible channel corruption or wrong key/IV.');
end

% Save decrypted file
fid = fopen(decFileOut, 'wb');
fwrite(fid, plain_received, 'uint8');
fclose(fid);
fprintf('STEP REC-3: Decrypted file saved as "%s".\n\n', decFileOut);

% Compute SHA-512 of decrypted file (to compare)
mdv = java.security.MessageDigest.getInstance('SHA-512');
mdv.update(int8(plain_received));
hash_recv_java = mdv.digest();  % Java byte[]
hash_recv_hex = lower(reshape(dec2hex(typecast(int8ToUint8Array(hash_recv_java),'uint8'))',1,[]));
fprintf('STEP REC-4: SHA-512 of received/decrypted file (hex, truncated):\n%s...\n\n', hash_recv_hex(1:min(200,numel(hash_recv_hex))));

% Verify signature: signatureBig_rx^e mod n -> should equal original hash
decrypted_hash_big = signatureBig_rx.modPow(e_rsa, n_rsa);
dec_hash_str = char(decrypted_hash_big.toString(16));
fprintf('STEP REC-5: Decrypted signature value (hex, truncated):\n%s...\n\n', dec_hash_str(1:min(200,numel(dec_hash_str))));

% Compare BigIntegers (constructed from received file hash)
hash_recv_big = java.math.BigInteger(1, int8ToUint8Array(hash_recv_java));
if decrypted_hash_big.equals(hash_recv_big)
    fprintf('✅ Signature verification SUCCESS: file is authentic & untampered.\n');
else
    fprintf('❌ Signature verification FAILED: possible tampering or transmission corruption.\n');
end

fprintf('\n====================================================================\n');
fprintf(' END OF MASTER DEMO (WITH EVE)\n');
fprintf('====================================================================\n\n');

end  % end of main function


%% ---------------- Eve helper routines ----------------

function blob_rx = eve_attack_transport_blob(blob_rx, nFlips)
    % Eve flips `nFlips` random bytes in transport blob.
    % blob_rx is uint8 vector.
    if nFlips <= 0
        return
    end
    L = numel(blob_rx);
    if L == 0
        return
    end
    for k = 1:nFlips
        idx = randi(L);
        % flip a random bit within the chosen byte
        bitPos = randi(8);
        blob_rx(idx) = bitxor(blob_rx(idx), bitshift(uint8(1), bitPos-1));
    end
end

function sig_ascii_rx = eve_attack_signature_ascii(sig_ascii_rx, nNibbleFlips)
    % Eve flips hex nibbles in ASCII hex signature.
    % sig_ascii_rx is uint8 vector containing ASCII hex characters (0-9a-f).
    if nNibbleFlips <= 0
        return
    end
    s = char(sig_ascii_rx(:)');  % string
    L = strlength(s);
    if L == 0
        return
    end
    % Build valid hex chars
    hexChars = ['0':'9' 'a':'f'];
    for k = 1:nNibbleFlips
        pos = randi([1 L]);
        % choose a different hex char than current (preserve hex charset)
        cur = lower(s(pos));
        % if current is not a hex char (shouldn't happen), replace with '0'
        if ~any(cur == hexChars)
            newChar = hexChars(randi(numel(hexChars)));
        else
            choices = hexChars(hexChars ~= cur);
            newChar = choices(randi(numel(choices)));
        end
        s(pos) = newChar;
    end
    sig_ascii_rx = uint8(s);
end


%% ---------------- Helper functions (copied from original) ----------------

function ciphertext = aes_encrypt_bytes(data, key, iv)
    % AES-CBC encryption (PKCS#7 padding) using Java Cipher via MATLAB
    import javax.crypto.*;
    import javax.crypto.spec.*;
    keySpec = SecretKeySpec(key, 'AES');
    ivSpec  = IvParameterSpec(iv);

    % PKCS#7 padding
    blockSize = 16;
    padLen = blockSize - mod(length(data), blockSize);
    if padLen == 0, padLen = blockSize; end
    dataPadded = [data(:)' repmat(uint8(padLen), 1, padLen)];

    cipher = Cipher.getInstance('AES/CBC/NoPadding');
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
    ciphertext = typecast(cipher.doFinal(dataPadded), 'uint8');
end

function plaintext = aes_decrypt_bytes(ciphertext, key, iv)
    % AES-CBC decryption (PKCS#7 removal)
    import javax.crypto.*;
    import javax.crypto.spec.*;
    keySpec = SecretKeySpec(key, 'AES');
    ivSpec  = IvParameterSpec(iv);

    cipher = Cipher.getInstance('AES/CBC/NoPadding');
    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
    decryptedBytes = typecast(cipher.doFinal(ciphertext), 'uint8');

    % Remove PKCS#7 padding
    padLen = double(decryptedBytes(end));
    if padLen < 1 || padLen > 16
        error('Invalid padding length detected during unpadding.');
    end
    plaintext = decryptedBytes(1:end-padLen);
end

function arr = int8ToUint8Array(javaArr)
    % Convert Java int8[] (signed -128..127) to MATLAB uint8 (0..255)
    if isempty(javaArr)
        arr = uint8([]);
        return
    end
    len = int32(numel(javaArr));
    arr = zeros(1,len,'uint8');
    for k=1:len
        v = int32(javaArr(k));
        if v < 0, v = v + 256; end
        arr(k) = uint8(v);
    end
end

function received = simulate_channel(data, errorProb)
    % Simulate a lossy channel that may flip random bits in bytes.
    % - data : a uint8 vector (can be ASCII byte representation or raw bytes)
    % - errorProb : per-byte probability of injecting a random bit flip
    % returned 'received' has same size as data (uint8).
    received = uint8(data);
    if errorProb <= 0
        return
    end
    for i = 1:length(data)
        if rand < errorProb
            % flip 1 random bit in this byte
            bitPos = randi([1 8]);
            received(i) = bitxor(received(i), bitshift(uint8(1), bitPos-1));
        end
    end
end
