clc; clear; close all;

%% Step 1: Key Generation
fprintf('--- RSA Key Generation ---\n');

% Choose two prime numbers (small for demo, use large primes in real life)
p = 61;
q = 53;

n = p * q;                  % Modulus
phi_n = (p-1) * (q-1);      % Euler Totient

% Choose public exponent e (coprime with phi_n)
e = 17;

% Compute private exponent d (modular inverse of e mod phi_n)
d = modInverse(e, phi_n);

fprintf('Public Key (e, n): (%d, %d)\n', e, n);
fprintf('Private Key (d, n): (%d, %d)\n\n', d, n);

%% Step 2: Sender creates a hash of the message
fprintf('--- Message Hashing ---\n');
message = 'This is the file hash value';
hash_val = sum(double(message));   % Toy hash (sum of ASCII values)
fprintf('Message: %s\n', message);
fprintf('Simulated Hash Value: %d\n\n', hash_val);

%% Step 3: Signature Generation (Sender)
fprintf('--- Signature Generation ---\n');
signature = powermod(hash_val, d, n);   % signature = hash^d mod n
fprintf('Digital Signature (encrypted hash): %d\n\n', signature);

%% Step 4: Signature Verification (Receiver)
fprintf('--- Signature Verification ---\n');
% Receiver "decrypts" the signature using public key
decrypted_hash = powermod(signature, e, n);
fprintf('Decrypted Hash from Signature: %d\n', decrypted_hash);

% Receiver computes hash of received message
received_hash = sum(double(message));
fprintf('Receiver Computed Hash: %d\n', received_hash);

% Verify
if decrypted_hash == received_hash
    fprintf('\n Signature Verified: Message is Authentic & Untampered.\n');
else
    fprintf('\n Signature Verification Failed: Message may be Tampered.\n');
end

%% --- Helper Functions ---

function inv = modInverse(a, m)
    % Extended Euclidean Algorithm to find modular inverse
    [g, x, ~] = gcdExtended(a, m);
    if g ~= 1
        error('Modular inverse does not exist!');
    else
        inv = mod(x, m);
    end
end

function [g, x, y] = gcdExtended(a, b)
    % Extended Euclidean Algorithm
    if a == 0
        g = b; x = 0; y = 1;
    else
        [g, x1, y1] = gcdExtended(mod(b, a), a);
        x = y1 - floor(b/a) * x1;
        y = x1;
    end
end

function result = powermod(base, exp, modn)
    % Fast modular exponentiation
    result = 1;
    base = mod(base, modn);
    while exp > 0
        if mod(exp,2)==1
            result = mod(result*base, modn);
        end
        exp = floor(exp/2);
        base = mod(base*base, modn);
    end
end
