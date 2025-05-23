import unittest
import threading
import time
import sys
import os
import io

# Add the src directory to the Python path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from src.common.utils import mod_inv, bytes_to_long, long_to_bytes, serialize_data, deserialize_data
from src.common.crypto_utils import ElGamal, derive_shared_secret, get_inverse_modulo_order, \
    encrypt_message_with_elgamal_shared_secret, \
    decrypt_message_with_elgamal_shared_secret
from src.sender.sender import Sender
from src.receiver.receiver import Receiver


# Temporarily suppress stdout/stderr to avoid polluting test output with logs
class SuppressOutput:
    def __enter__(self):
        self._original_stdout = sys.stdout
        self._original_stderr = sys.stderr
        sys.stdout = io.StringIO()
        sys.stderr = io.StringIO()

    def __exit__(self, exc_type, exc_val, exc_tb):
        sys.stdout = self._original_stdout
        sys.stderr = self._original_stderr


class TestCryptoUtils(unittest.TestCase):

    def test_mod_inv(self):
        with SuppressOutput():
            self.assertEqual(mod_inv(3, 11), 4)  # 3*4 = 12 = 1 mod 11
            self.assertEqual(mod_inv(17, 31), 29)  # 17*29 = 493 = 1 mod 31
            with self.assertRaises(ValueError):
                mod_inv(2, 4)  # gcd(2,4) != 1

    def test_bytes_long_conversion(self):
        with SuppressOutput():
            test_str = "Hello, world! This is a long string for testing purposes."
            test_bytes = test_str.encode('utf-8')
            test_int = bytes_to_long(test_bytes)
            converted_bytes = long_to_bytes(test_int)
            self.assertEqual(converted_bytes, test_bytes)

            # Test with padding
            padded_bytes = long_to_bytes(test_int, block_size=64)
            self.assertEqual(len(padded_bytes), 64)
            # Make sure it can be converted back to the original value (though stripping padding is for specific use)
            self.assertEqual(bytes_to_long(padded_bytes), test_int)

    def test_elgamal_parameters(self):
        with SuppressOutput():
            # Use a smaller bit_length for faster testing
            p, g = ElGamal(1, 1).generate_elgamal_parameters(bit_length=256)
            self.assertTrue(p > 1 and g > 1 and g < p)
            self.assertTrue(len(str(p)) >= 77)  # 256 bits is approx 77 decimal digits
            # Add a check for primality if necessary (more complex, often relies on library)
            # For now, trust cryptography.hazmat.primitives.asymmetric.dh

    def test_elgamal_shared_secret_operations(self):
        with SuppressOutput():
            p, g = ElGamal(1, 1).generate_elgamal_parameters(bit_length=256)
            elgamal = ElGamal(p, g)

            # Simulate Alice's keys
            alice_x0 = elgamal.generate_private_key()
            alice_Y0 = elgamal.compute_public_key(alice_x0)

            # Simulate Bob's key
            bob_k = random.randint(1, p - 2)

            # Bob computes K0 = Y0^k mod p (if he chose M0)
            bob_K0 = derive_shared_secret(alice_Y0, bob_k, p)

            # Alice computes S0 = K0^(x0_inv) mod p
            x0_inv = get_inverse_modulo_order(alice_x0, p - 1)
            alice_S0 = derive_shared_secret(bob_K0, x0_inv, p)

            # Bob computes his decryption secret = g^k mod p
            bob_dec_secret = derive_shared_secret(g, bob_k, p)

            # Crucial check: Is alice_S0 equal to bob_dec_secret? They should be!
            # K0 = Y0^k = (g^x0)^k = g^(x0*k)
            # S0 = K0^(x0_inv) = (g^(x0*k))^(x0_inv) = g^(x0*k*x0_inv) = g^k (mod p)
            self.assertEqual(alice_S0, bob_dec_secret)

            # Test encryption/decryption
            original_msg_int = bytes_to_long(b"Test message")
            encrypted_msg = encrypt_message_with_elgamal_shared_secret(original_msg_int, alice_S0, p)
            decrypted_msg = decrypt_message_with_elgamal_shared_secret(encrypted_msg, bob_dec_secret, p)

            self.assertEqual(decrypted_msg, original_msg_int)


class TestObliviousTransferProtocol(unittest.TestCase):

    def run_sender_in_thread(self, sender_instance):
        try:
            sender_instance.start()
        except Exception as e:
            self.sender_error = e

    def run_receiver_in_thread(self, receiver_instance):
        try:
            receiver_instance.start()
        except Exception as e:
            self.receiver_error = e

    def test_ot_protocol_m0(self):
        # Suppress logging for cleaner test output
        with SuppressOutput():
            self.sender_error = None
            self.receiver_error = None

            m0_text = "This is the secret message for choice 0."
            m1_text = "This is the secret message for choice 1."

            sender = Sender(host='127.0.0.1', port=50000, bit_length=512)  # Use a different port for tests
            sender.set_messages(m0_text, m1_text)

            receiver = Receiver(host='127.0.0.1', port=50000)
            receiver.set_choice(0)  # Receiver wants M0

            # Start sender and receiver in separate threads
            sender_thread = threading.Thread(target=self.run_sender_in_thread, args=(sender,))
            receiver_thread = threading.Thread(target=self.run_receiver_in_thread, args=(receiver,))

            sender_thread.start()
            # Give sender a moment to bind and listen
            time.sleep(0.5)
            receiver_thread.start()

            sender_thread.join(timeout=10)  # Wait for threads to finish, with timeout
            receiver_thread.join(timeout=10)

            # Check for errors in threads
            if sender_thread.is_alive():
                self.fail("Sender thread did not complete within timeout.")
            if receiver_thread.is_alive():
                self.fail("Receiver thread did not complete within timeout.")

            if self.sender_error:
                self.fail(f"Sender thread raised an error: {self.sender_error}")
            if self.receiver_error:
                self.fail(f"Receiver thread raised an error: {self.receiver_error}")

            # Assertions
            self.assertIsNotNone(receiver.received_message)
            self.assertEqual(receiver.received_message, m0_text)
            self.assertNotIn(m1_text, receiver.received_message)  # Ensure M1 was not received

    def test_ot_protocol_m1(self):
        with SuppressOutput():
            self.sender_error = None
            self.receiver_error = None

            m0_text = "Message 0 content."
            m1_text = "Message 1 content."

            sender = Sender(host='127.0.0.1', port=50001, bit_length=512)  # Different port
            sender.set_messages(m0_text, m1_text)

            receiver = Receiver(host='127.0.0.1', port=50001)
            receiver.set_choice(1)  # Receiver wants M1

            sender_thread = threading.Thread(target=self.run_sender_in_thread, args=(sender,))
            receiver_thread = threading.Thread(target=self.run_receiver_in_thread, args=(receiver,))

            sender_thread.start()
            time.sleep(0.5)
            receiver_thread.start()

            sender_thread.join(timeout=10)
            receiver_thread.join(timeout=10)

            if sender_thread.is_alive():
                self.fail("Sender thread did not complete within timeout.")
            if receiver_thread.is_alive():
                self.fail("Receiver thread did not complete within timeout.")

            if self.sender_error:
                self.fail(f"Sender thread raised an error: {self.sender_error}")
            if self.receiver_error:
                self.fail(f"Receiver thread raised an error: {self.receiver_error}")

            self.assertIsNotNone(receiver.received_message)
            self.assertEqual(receiver.received_message, m1_text)
            self.assertNotIn(m0_text, receiver.received_message)  # Ensure M0 was not received

    def test_ot_connection_refused(self):
        with SuppressOutput():
            receiver = Receiver(host='127.0.0.1', port=50002)  # Try a port where no sender is running
            receiver.set_choice(0)

            # Expect ConnectionRefusedError
            with self.assertRaises(ConnectionRefusedError):
                receiver.start()


if __name__ == '__main__':
    unittest.main()
