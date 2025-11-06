clc; clear; close all;
% Set your file name or full path here
file = 'A-Novel-Approach-for-Ticket-Generation-and-Validation-Using-RSA-and-Keccak-Algorithms.pdf';  % Change to your PDF filename

% Compute SHA-512 hash
[hexDigest, ~] = sha512_of_file(file);

% Print the 128-character SHA-512 hash in Command Window
fprintf('SHA-512: (%s)\n', hexDigest);

% --- Local functions below ---

function [hexDigest, rawBytes] = sha512_of_file(filepath)
    if ~ischar(filepath) && ~isstring(filepath)
        error('Filepath must be a string');
    end
    filepath = char(filepath);
    if ~exist(filepath, 'file')
        error('File not found: %s', filepath);
    end
    md = java.security.MessageDigest.getInstance('SHA-512');
    fid = fopen(filepath, 'rb');
    CHUNK = 65536;
    while ~feof(fid)
        data = fread(fid, CHUNK, '*uint8');
        if ~isempty(data)
            md.update(int8(data));
        end
    end
    fclose(fid);
    digest_java = md.digest();
    rawBytes = zeros(1, numel(digest_java), 'uint8');
    for i = 1:numel(digest_java)
        rawBytes(i) = uint8(double(digest_java(i)) + 256 * (digest_java(i) < 0));
    end
    hexDigest = bytes2hex(rawBytes);
end

function hexStr = bytes2hex(byteArray)
    hexChars = '0123456789abcdef';
    hexStr = blanks(numel(byteArray)*2);
    idx = 1;
    for k = 1:numel(byteArray)
        b = byteArray(k);
        hexStr(idx)   = hexChars(bitshift(b,-4)+1);
        hexStr(idx+1) = hexChars(bitand(b,15)+1);
        idx = idx + 2;
    end
end
