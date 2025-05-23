import random
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from src.common.utils import mod_inv, bytes_to_long, long_to_bytes  # Import from our utils.py

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class ElGamal:
    """
    A class implementing basic ElGamal operations (key generation, encryption, decryption)
    suitable for the 1-of-2 Oblivious Transfer protocol.
    Note: This is a simplified ElGamal implementation focused on the OT protocol's needs,
    not a general-purpose ElGamal library.
    """

    def __init__(self, p, g):
        """
        Initializes the ElGamal scheme with a prime p and a generator g.
        Args:
            p (int): A large prime number.
            g (int): A generator of the cyclic group modulo p.
        """
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
        x is chosen from {1, ..., p-2}.
        """
        # The order of the group for p is p-1. So, x should be chosen from [1, p-2] or [1, p-1]
        # depending on specific security considerations for discrete logarithm.
        # For simplicity and standard practice, we choose x from 1 to p-2.
        x = random.randint(1, self.p - 2)
        logging.debug(f"Generated ElGamal private key (x): {x}")
        return x

    def compute_public_key(self, private_key):
        """
        Computes the public key (Y) from a private key (x). Y = g^x mod p.
        """
        public_key = pow(self.g, private_key, self.p)
        logging.debug(f"Computed ElGamal public key (Y): {public_key}")
        return public_key

    # Note: For our OT protocol, the 'encryption' is slightly different.
    # Alice uses her secret x to transform Bob's K_i.
    # Bob uses his secret k to transform Alice's Y_i.

    def generate_elgamal_parameters(self, bit_length=1024):
        """
        Generates suitable Diffie-Hellman parameters (p, g) which can be used for ElGamal.
        This function uses the cryptography library to ensure secure parameters.
        Args:
            bit_length (int): The desired bit length for the prime p.
        Returns:
            tuple: (p, g) where p is a large prime and g is a generator.
        """
        logging.info(f"Generating {bit_length}-bit DH parameters for ElGamal...")
        # Use a safe prime group (generator=2 is common for DH and ElGamal)
        parameters = dh.generate_parameters(generator=2, key_size=bit_length, backend=default_backend())
        p = parameters.parameter_numbers().p
        g = parameters.parameter_numbers().g
        logging.info(f"Generated p with {p.bit_length()} bits ({len(str(p))} decimal digits) and g={g}.")
        if len(str(p)) < 100:
            logging.warning(
                f"Generated prime has {len(str(p))} decimal digits, which is less than 100. Consider increasing bit_length.")
        return p, g


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
    In the OT context, this is M_i * S_i mod p.
    Args:
        message_int (int): The message as an integer.
        shared_secret (int): The shared secret derived in ElGamal.
        modulus (int): The prime modulus p.
    Returns:
        int: The 'ciphertext' C_i.
    """
    # Ensure message_int is within the valid range [0, p-1]
    if not (0 <= message_int < modulus):
        logging.warning(
            f"Message integer {message_int} is outside the valid range [0, {modulus - 1}] for ElGamal encryption. It will be taken modulo modulus.")

    # Check for zero shared_secret, which would make decryption impossible if it's supposed to be multiplicative
    if shared_secret == 0:
        raise ValueError("Shared secret cannot be zero for multiplicative encryption.")

    return (message_int * shared_secret) % modulus


def decrypt_message_with_elgamal_shared_secret(ciphertext_int, shared_secret, modulus):
    """
    'Decrypts' a ciphertext integer using a shared secret.
    In the OT context, this is C_b * S_b^-1 mod p.
    Args:
        ciphertext_int (int): The ciphertext as an integer.
        shared_secret (int): The shared secret used for decryption.
        modulus (int): The prime modulus p.
    Returns:
        int: The decrypted message as an integer.
    """
    if shared_secret == 0:
        raise ValueError("Shared secret cannot be zero for decryption. Inverse does not exist.")

    # Calculate the modular inverse of the shared secret modulo modulus
    inv_shared_secret = mod_inv(shared_secret, modulus)

    return (ciphertext_int * inv_shared_secret) % modulus


# Example usage (for testing purposes, not part of the main flow):
if __name__ == '__main__':
    logging.info("--- Testing crypto_utils.py ---")

    # Generate parameters
    p_test, g_test = ElGamal(1, 1).generate_elgamal_parameters(bit_length=512)  # Smaller bits for quicker testing

    elgamal = ElGamal(p_test, g_test)

    # --- Test modular inverse ---
    try:
        a_inv = get_inverse_modulo_order(5, 7)  # Should be 3 (5*3=15 = 1 mod 7)
        logging.info(f"Inverse of 5 mod 7: {a_inv}")
        assert a_inv == 3

        a_inv_large = get_inverse_modulo_order(12345, p_test - 1)  # Test with large number
        logging.info(f"Inverse of 12345 mod (p-1) for large p: {a_inv_large}")
        assert (12345 * a_inv_large) % (p_test - 1) == 1

        # Test case where inverse doesn't exist
        try:
            get_inverse_modulo_order(2, 4)
            logging.error("Expected ValueError for gcd(2,4)!=1, but none occurred.")
        except ValueError as e:
            logging.info(f"Correctly caught expected error: {e}")

    except Exception as e:
        logging.error(f"Error during modular inverse test: {e}")

    # --- Test encryption/decryption with shared secret ---
    try:
        # Simulate Alice's x and Bob's k
        alice_x = elgamal.generate_private_key()
        bob_k = random.randint(1, p_test - 2)

        # Simulate Alice's public key
        alice_Y = elgamal.compute_public_key(alice_x)

        # Simulate Bob calculating his K (one of K0 or K1)
        bob_K_choice = derive_shared_secret(alice_Y, bob_k, p_test)  # This would be K_0 or K_1 from Bob

        # Simulate Alice computing her S (one of S0 or S1)
        alice_S_choice = derive_shared_secret(bob_K_choice, get_inverse_modulo_order(alice_x, p_test - 1), p_test)

        # Simulate Bob computing his S_b (g^k mod p)
        bob_decryption_secret = derive_shared_secret(elgamal.g, bob_k, p_test)

        # Test encryption and decryption
        original_message = 12345678901234567890  # A large integer message

        encrypted_message = encrypt_message_with_elgamal_shared_secret(
            original_message, alice_S_choice, p_test
        )
        logging.info(f"Original message: {original_message}")
        logging.info(f"Encrypted message: {encrypted_message}")

        decrypted_message = decrypt_message_with_elgamal_shared_secret(
            encrypted_message, bob_decryption_secret, p_test
        )
        logging.info(f"Decrypted message: {decrypted_message}")

        assert original_message % p_test == decrypted_message % p_test, "Decryption failed!"
        logging.info("Encryption/Decryption with shared secret test successful!")

    except Exception as e:
        logging.error(f"Error during encryption/decryption test: {e}")