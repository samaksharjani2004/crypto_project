function aes_pdf_demo()
    % File names
    inputFile  = 'Adaptive.pdf';        % Original PDF
    encFile    = 'Adaptive_encrypted.bin'; % Encrypted output
    decFile    = 'Adaptive_decrypted.pdf'; % Decrypted output

    % Key and IV
    key = '12345678901234567890123456789012'; % 32 chars = 256-bit key
    iv  = '1234567890123456';                 % 16 chars IV

    %% Read PDF as bytes
    fid = fopen(inputFile, 'rb');
    if fid == -1, error('Cannot open input PDF'); end
    data = fread(fid, inf, '*uint8');
    fclose(fid);

    %% Encrypt
    ciphertext = aes_encrypt_bytes(data, key, iv);

    % Write encrypted PDF
    fid = fopen(encFile, 'wb');
    fwrite(fid, ciphertext, 'uint8');
    fclose(fid);
    disp(['Encrypted file saved as: ', encFile]);

    %% Decrypt
    decrypted = aes_decrypt_bytes(ciphertext, key, iv);

    % Write decrypted PDF
    fid = fopen(decFile, 'wb');
    fwrite(fid, decrypted, 'uint8');
    fclose(fid);
    disp(['Decrypted file saved as: ', decFile]);
end

%% AES Encrypt for bytes
function ciphertext = aes_encrypt_bytes(data, key, iv)
    import javax.crypto.*
    import javax.crypto.spec.*

    keyBytes = uint8(key(:)');
    ivBytes  = uint8(iv(:)');

    % PKCS#7 padding
    blockSize = 16;
    padLen = blockSize - mod(length(data), blockSize);
    dataPadded = [data(:)' repmat(uint8(padLen), 1, padLen)];

    % Java AES CBC NoPadding
    cipher = Cipher.getInstance('AES/CBC/NoPadding');
    keySpec = SecretKeySpec(keyBytes, 'AES');
    ivSpec  = IvParameterSpec(ivBytes);
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

    ciphertext = typecast(cipher.doFinal(dataPadded), 'uint8');
end

%% AES Decrypt for bytes
function plaintext = aes_decrypt_bytes(ciphertext, key, iv)
    import javax.crypto.*
    import javax.crypto.spec.*

    keyBytes = uint8(key(:)');
    ivBytes  = uint8(iv(:)');

    cipher = Cipher.getInstance('AES/CBC/NoPadding');
    keySpec = SecretKeySpec(keyBytes, 'AES');
    ivSpec  = IvParameterSpec(ivBytes);
    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

    decryptedBytes = typecast(cipher.doFinal(ciphertext), 'uint8');

    % Remove PKCS#7 padding
    padLen = double(decryptedBytes(end));
    plaintext = decryptedBytes(1:end-padLen);
end
