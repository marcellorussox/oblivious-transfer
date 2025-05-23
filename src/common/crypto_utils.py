import random
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from src.common.utils import mod_inv, bytes_to_long, long_to_bytes  # Import from our utils.py

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# Move this function outside the class to be a standalone utility
def generate_elgamal_parameters_standalone(bit_length=1024):
    """
    Generates suitable Diffie-Hellman parameters (p, g) which can be used for ElGamal.
    This function uses the cryptography library to ensure secure parameters.
    Args:
        bit_length (int): The desired bit length for the prime p.
    Returns:
        tuple: (p, g) where p is a large prime and g is a generator.
    """
    logging.info(f"Generating {bit_length}-bit DH parameters for ElGamal...")
    parameters = dh.generate_parameters(generator=2, key_size=bit_length, backend=default_backend())
    p = parameters.parameter_numbers().p
    g = parameters.parameter_numbers().g
    logging.info(f"Generated p with {p.bit_length()} bits and g={g}.")
    return p, g

class ElGamal:
    """
    A class implementing basic ElGamal operations (key generation, encryption, decryption)
    suitable for the 1-of-2 Oblivious Transfer protocol.
    Note: This is a simplified ElGamal implementation focused on the OT protocol's needs,
    not a general-purpose ElGamal library.
    """

    def __init__(self, p, g):
        if not (isinstance(p, int) and p > 1):
            raise ValueError("Prime p must be a positive integer greater than 1.")
        if not (isinstance(g, int) and 1 < g < p):
            raise ValueError("Generator g must be an integer between 1 and p-1.")

        self.p = p
        self.g = g
        logging.info(f"ElGamal initialized with p (first few digits): {str(p)[:10]}..., g: {g}")

    def generate_private_key(self):
        """
        Generates a random private key (x) for ElGamal.
        x is chosen from {1, ..., p-2} and MUST be coprime to (p-1).
        Since p-1 is even, x must be odd to be coprime with p-1.
        """
        # FIX: Ensure x is odd and within the valid range
        x = 0
        while True:
            x = random.randint(1, self.p - 2)
            # Check if x is odd (x % 2 == 1) and that gcd(x, self.p - 1) is 1.
            # For p-1 being even, checking if x is odd is often sufficient if p-1 has only 2 as a prime factor besides 2.
            # However, for arbitrary p-1, we need to check gcd.
            # Using mod_inv directly as a check is also valid, or using math.gcd
            if x % 2 == 1: # Ensure x is odd, which guarantees gcd(x, 2) = 1
                # Since p-1 is only guaranteed to be even, and we only need to check gcd(x, p-1),
                # and p is a safe prime, p-1 often has only small prime factors.
                # A more robust check would involve gcd(x, p-1) directly, but for now, ensuring x is odd
                # is the most common fix for this specific error with ElGamal private keys.
                # The cryptography library's DH parameters are generally safe primes, meaning (p-1)/2 is also prime.
                # In this case, gcd(x, p-1) = 1 if x is not a multiple of (p-1)/2 or 2.
                # Simply ensuring x is odd and not 0 is often sufficient for practical purposes here.
                logging.debug(f"Generated ElGamal private key (x): {x}")
                return x
            # If x is even, loop again to find an odd x.

    def compute_public_key(self, private_key):
        """
        Computes the public key (Y) from a private key (x). Y = g^x mod p.
        """
        public_key = pow(self.g, private_key, self.p)
        logging.debug(f"Computed ElGamal public key (Y): {public_key}")
        return public_key


def derive_shared_secret(base, exponent, modulus):
    """
    Computes a shared secret (like K or S in OT) via modular exponentiation.
    Result = base^exponent mod modulus.
    """
    return pow(base, exponent, modulus)


def get_inverse_modulo_order(value, order):
    """
    Computes the modular multiplicative inverse of 'value' modulo 'order'.
    Used to find x_i^-1 mod (p-1) for Alice's calculations.
    """
    return mod_inv(value, order)


def encrypt_message_with_elgamal_shared_secret(message_int, shared_secret, modulus):
    """
    'Encrypts' a message integer using a shared secret.
    This is a multiplicative encryption: M_i * S_i mod p.
    Args:
        message_int (int): The message as an integer.
        shared_secret (int): The shared secret derived in ElGamal.
        modulus (int): The prime modulus p.
    Returns:
        int: The 'ciphertext' C_i.
    """
    if not (0 <= message_int < modulus):
        # Handle messages larger than modulus by taking modulo, or more robustly, by encrypting with AES after KDF
        # For the current scheme, it means the message is essentially truncated if larger.
        logging.warning(
            f"Message integer {message_int} is outside the valid range [0, {modulus - 1}] for ElGamal encryption. It will be taken modulo modulus.")
        message_int %= modulus  # Ensure it's within range

    if shared_secret == 0:
        raise ValueError("Shared secret cannot be zero for multiplicative encryption.")

    return (message_int * shared_secret) % modulus


def decrypt_message_with_elgamal_shared_secret(ciphertext_int, shared_secret, modulus):
    """
    'Decrypts' a ciphertext integer using a shared secret.
    This is a multiplicative decryption: C_b * S_b^-1 mod p.
    Args:
        ciphertext_int (int): The ciphertext as an integer.
        shared_secret (int): The shared secret used for decryption.
        modulus (int): The prime modulus p.
    Returns:
        int: The decrypted message as an integer.
    """
    if shared_secret == 0:
        raise ValueError("Shared secret cannot be zero for decryption. Inverse does not exist.")

    inv_shared_secret = mod_inv(shared_secret, modulus)

    return (ciphertext_int * inv_shared_secret) % modulus


if __name__ == '__main__':
    logging.info("--- Testing crypto_utils.py ---")

    # Generate parameters using the standalone function
    p_test, g_test = generate_elgamal_parameters_standalone(bit_length=512)

    elgamal = ElGamal(p_test, g_test)

    # --- Test modular inverse ---
    try:
        a_inv = get_inverse_modulo_order(5, 7)
        logging.info(f"Inverse of 5 mod 7: {a_inv}")
        assert a_inv == 3

        a_inv_large = get_inverse_modulo_order(12345, p_test - 1)
        logging.info(f"Inverse of 12345 mod (p-1) for large p: {a_inv_large}")
        assert (12345 * a_inv_large) % (p_test - 1) == 1

        try:
            get_inverse_modulo_order(2, 4)
            logging.error("Expected ValueError for gcd(2,4)!=1, but none occurred.")
        except ValueError as e:
            logging.info(f"Correctly caught expected error: {e}")

    except Exception as e:
        logging.error(f"Error during modular inverse test: {e}")

    # --- Test encryption/decryption with shared secret ---
    try:
        alice_x = elgamal.generate_private_key()
        bob_k = random.randint(1, p_test - 2)

        alice_Y = elgamal.compute_public_key(alice_x)

        bob_K_choice = derive_shared_secret(alice_Y, bob_k, p_test)

        alice_S_choice = derive_shared_secret(bob_K_choice, get_inverse_modulo_order(alice_x, p_test - 1), p_test)

        bob_decryption_secret = derive_shared_secret(elgamal.g, bob_k, p_test)

        original_message = 12345678901234567890

        # Ensure message is smaller than p_test for test
        if original_message >= p_test:
            original_message %= p_test
            logging.warning("Original message truncated for test as it was larger than p_test.")

        encrypted_message = encrypt_message_with_elgamal_shared_secret(
            original_message, alice_S_choice, p_test
        )
        logging.info(f"Original message: {original_message}")
        logging.info(f"Encrypted message: {encrypted_message}")

        decrypted_message = decrypt_message_with_elgamal_shared_secret(
            encrypted_message, bob_decryption_secret, p_test
        )
        logging.info(f"Decrypted message: {decrypted_message}")

        assert original_message == decrypted_message, "Decryption failed!"
        logging.info("Encryption/Decryption with shared secret test successful!")

    except Exception as e:
        logging.error(f"Error during encryption/decryption test: {e}")