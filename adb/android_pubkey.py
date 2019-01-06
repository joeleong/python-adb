"""This file implements encoding and decoding logic for Android's custom RSA
public key binary format. Public keys are stored as a sequence of
little-endian 32 bit words. Note that Android only supports little-endian
processors, so we don't do any byte order conversions when parsing the binary
struct.

Structure from:
https://github.com/aosp-mirror/platform_system_core/blob/c55fab4a59cfa461857c6a61d8a0f1ae4591900c/libcrypto_utils/android_pubkey.c

typedef struct RSAPublicKey {
    // Modulus length. This must be ANDROID_PUBKEY_MODULUS_SIZE.
    uint32_t modulus_size_words;

    // Precomputed montgomery parameter: -1 / n[0] mod 2^32
    uint32_t n0inv;

    // RSA modulus as a little-endian array.
    uint8_t modulus[ANDROID_PUBKEY_MODULUS_SIZE];

    // Montgomery parameter R^2 as a little-endian array of little-endian words.
    uint8_t rr[ANDROID_PUBKEY_MODULUS_SIZE];

    // RSA modulus: 3 or 65537
    uint32_t exponent;
} RSAPublicKey;"""


from __future__ import print_function

import os
import six
import base64
import socket
import struct

import Crypto.Util
import Crypto.PublicKey.RSA


# Size of an RSA modulus such as an encrypted block or a signature.
ANDROID_PUBKEY_MODULUS_SIZE = (2048 // 8)

# Size of an encoded RSA key.
ANDROID_PUBKEY_ENCODED_SIZE = \
    (3 * 4 + 2 * ANDROID_PUBKEY_MODULUS_SIZE)
  # (3 * sizeof(uint32_t) + 2 * ANDROID_PUBKEY_MODULUS_SIZE)

# Size of the RSA modulus in words.
ANDROID_PUBKEY_MODULUS_SIZE_WORDS = (ANDROID_PUBKEY_MODULUS_SIZE // 4)


def _to_bytes(n, length, endianess='big'):
    """partial python2 compatibility with int.to_bytes
    https://stackoverflow.com/a/20793663"""
    if six.PY2:
        h = '{:x}'.format(n)
        s = ('0' * (len(h) % 2) + h).zfill(length * 2).decode('hex')
        return s if endianess == 'big' else s[::-1]
    return n.to_bytes(length, endianess)


def decode_pubkey(public_key):
    """decodes a public RSA key stored in Android's custom binary format"""
    binary_key_data = base64.b64decode(public_key)
    key_struct = struct.unpack(('<LL' +
        'B' * ANDROID_PUBKEY_MODULUS_SIZE +
        'B' * ANDROID_PUBKEY_MODULUS_SIZE +
        'L'), binary_key_data)
    modulus_size_words = key_struct[0]
    n0inv = key_struct[1]
    modulus = reversed(key_struct[2: 2 + ANDROID_PUBKEY_MODULUS_SIZE])
    rr = reversed(key_struct[2 + ANDROID_PUBKEY_MODULUS_SIZE:
      2 + 2 * ANDROID_PUBKEY_MODULUS_SIZE])
    exponent = key_struct[-1]
    print('modulus_size_words:', hex(modulus_size_words))
    print('n0inv:', hex(n0inv))
    print('modulus: ', end='')
    print(*map(hex, modulus), sep=':')
    print('rr: ', end='')
    print(*map(hex, rr), sep=':')
    print('exponent:', hex(exponent))


def decode_pubkey_file(public_key_path):
    with open(public_key_path, 'rb') as fd:
      decode_pubkey(fd.read())


def encode_pubkey(private_key_path):
    """encodes a public RSA key into Android's custom binary format"""
    key = Crypto.PublicKey.RSA.import_key(private_key_path)

    # Store the modulus size.
    key_buffer = struct.pack('<L', ANDROID_PUBKEY_MODULUS_SIZE_WORDS)
    # Compute and store n0inv = -1 / N[0] mod 2^32.
    # BN_set_bit(r32, 32)
    r32 = 1 << 32
    # BN_mod(n0inv, key->n, r32, ctx)
    n0inv = key.n % r32
    # BN_mod_inverse(n0inv, n0inv, r32, ctx)
    n0inv = Crypto.Util.number.inverse(n0inv, r32)
    # BN_sub(n0inv, r32, n0inv)
    n0inv = r32 - n0inv
    key_buffer += struct.pack('<L', n0inv)

    # Store the modulus.
    key_buffer += _to_bytes(key.n, ANDROID_PUBKEY_MODULUS_SIZE, 'little')
    # Compute and store rr = (2^(rsa_size)) ^ 2 mod N.
    # BN_set_bit(rr, ANDROID_PUBKEY_MODULUS_SIZE * 8)
    rr = 1 << (ANDROID_PUBKEY_MODULUS_SIZE * 8)
    # BN_mod_sqr(rr, rr, key->n, ctx)
    rr = (rr ** 2) % key.n
    key_buffer += _to_bytes(rr, ANDROID_PUBKEY_MODULUS_SIZE, 'little')

    key_buffer += struct.pack('<L', key.e)
    return key_buffer


def get_user_info():
    username = os.getlogin()
    if not username:
        username = 'unknown'

    hostname = socket.gethostname()
    if not hostname:
        hostname = 'unknown'

    return ' ' + username + '@' + hostname


def write_public_keyfile(private_key_path, public_key_path):
    """write public keyfile to public_key_path in Android's custom
    RSA public key format given a path to a private keyfile"""
    with open(private_key_path, 'rb') as private_key_file:
        private_key = private_key_file.read()

    public_key = encode_pubkey(private_key)
    assert len(public_key) == ANDROID_PUBKEY_ENCODED_SIZE
    with open(public_key_path, 'wb') as public_key_file:
        public_key_file.write(base64.b64encode(public_key))
        public_key_file.write(get_user_info().encode())


def keygen(filepath):
    """generate adb public/private key
    private key stored in {filepath}
    public key stored in {filepath}.pub
    (existing files overwritten)

    Args:
      filepath: File path to write the private/public keypair
    """
    key = Crypto.PublicKey.RSA.generate(2048)
    with open(filepath, 'wb') as private_key_file:
        private_key_file.write(key.export_key(format='PEM', pkcs=8))

    write_public_keyfile(filepath, filepath + '.pub')
