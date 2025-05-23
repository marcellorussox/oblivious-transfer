import unittest
import threading
import time
import sys
import os
import io
import random
from queue import Queue  # FIX: Import Queue from the queue module

# Add the src directory to the Python path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from src.common.utils import mod_inv, bytes_to_long, long_to_bytes, serialize_data, deserialize_data
# Import the standalone function for parameter generation
from src.common.crypto_utils import ElGamal, generate_elgamal_parameters_standalone, \
    derive_shared_secret, get_inverse_modulo_order, \
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
            self.assertEqual(mod_inv(17, 31), 11)  # 17*11 = 187 = 1 mod 31
            with self.assertRaises(ValueError):
                mod_inv(2, 4)  # gcd(2,4) != 1

    def test_bytes_long_conversion(self):
        with SuppressOutput():
            test_str = "Hello, world! This is a long string for testing purposes."
            test_bytes = test_str.encode('utf-8')
            test_int = bytes_to_long(test_bytes)
            converted_bytes = long_to_bytes(test_int)
            self.assertEqual(converted_bytes, test_bytes)

            # Test with padding - ensure it converts back correctly (no unpadding needed for this assertion)
            padded_bytes = long_to_bytes(test_int, block_size=64)
            self.assertEqual(len(padded_bytes), 64)
            self.assertEqual(bytes_to_long(padded_bytes), test_int)  # Should still convert to the same int value

    def test_elgamal_parameters(self):
        with SuppressOutput():
            # FIX: Change bit_length to 512
            p, g = generate_elgamal_parameters_standalone(bit_length=512)
            self.assertTrue(p > 1 and g > 1 and g < p)
            # 512 bits is approx 154 decimal digits
            self.assertTrue(len(str(p)) >= 150)  # Adjusted for 512 bits

    def test_elgamal_shared_secret_operations(self):
        with SuppressOutput():
            # FIX: Change bit_length to 512
            p, g = generate_elgamal_parameters_standalone(bit_length=512)
            elgamal = ElGamal(p, g)  # Initialize ElGamal with valid p, g

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
            self.assertEqual(alice_S0, bob_dec_secret)

            # Test encryption/decryption
            original_msg_bytes = b"Test message for OT"
            original_msg_int = bytes_to_long(original_msg_bytes)

            # Ensure the integer message is smaller than p for direct modular arithmetic
            if original_msg_int >= p:
                original_msg_int %= p

            encrypted_msg = encrypt_message_with_elgamal_shared_secret(original_msg_int, alice_S0, p)
            decrypted_msg_int = decrypt_message_with_elgamal_shared_secret(encrypted_msg, bob_dec_secret, p)

            self.assertEqual(decrypted_msg_int, original_msg_int)


class TestObliviousTransferProtocol(unittest.TestCase):

    def run_sender_in_thread(self, sender_instance, error_queue):
        try:
            sender_instance.start()
        except Exception as e:
            error_queue.put(e)

    def run_receiver_in_thread(self, receiver_instance, error_queue):
        try:
            receiver_instance.start()
        except Exception as e:
            error_queue.put(e)

    def test_ot_protocol_m0(self):
        with SuppressOutput():
            # FIX: Use Queue from 'queue' module
            sender_error_queue = Queue()
            receiver_error_queue = Queue()

            m0_text = "This is the secret message for choice 0."
            m1_text = "This is the secret message for choice 1."

            sender = Sender(host='127.0.0.1', port=50000, bit_length=512)
            sender.set_messages(m0_text, m1_text)

            receiver = Receiver(host='127.0.0.1', port=50000)
            receiver.set_choice(0)  # Receiver wants M0

            sender_thread = threading.Thread(target=self.run_sender_in_thread, args=(sender, sender_error_queue))
            receiver_thread = threading.Thread(target=self.run_receiver_in_thread,
                                               args=(receiver, receiver_error_queue))

            sender_thread.start()
            time.sleep(3)  # Give more time for the Sender to set up
            receiver_thread.start()

            sender_thread.join(timeout=20)  # Increased timeout
            receiver_thread.join(timeout=20)

            # Check for errors in threads
            if not sender_error_queue.empty():
                self.fail(f"Sender thread raised an error: {sender_error_queue.get()}")
            if not receiver_error_queue.empty():
                self.fail(f"Receiver thread raised an error: {receiver_error_queue.get()}")

            if sender_thread.is_alive():
                self.fail("Sender thread did not complete within timeout.")
            if receiver_thread.is_alive():
                self.fail("Receiver thread did not complete within timeout.")

            # Assertions on receiver's final message
            self.assertIsNotNone(receiver.received_message)
            self.assertEqual(receiver.received_message, m0_text)
            self.assertNotIn(m1_text, receiver.received_message)

    def test_ot_protocol_m1(self):
        with SuppressOutput():
            # FIX: Use Queue from 'queue' module
            sender_error_queue = Queue()
            receiver_error_queue = Queue()

            m0_text = "Message 0 content."
            m1_text = "Message 1 content."

            sender = Sender(host='127.0.0.1', port=50001, bit_length=512)  # Different port
            sender.set_messages(m0_text, m1_text)

            receiver = Receiver(host='127.0.0.1', port=50001)
            receiver.set_choice(1)  # Receiver wants M1

            sender_thread = threading.Thread(target=self.run_sender_in_thread, args=(sender, sender_error_queue))
            receiver_thread = threading.Thread(target=self.run_receiver_in_thread,
                                               args=(receiver, receiver_error_queue))

            sender_thread.start()
            time.sleep(3)
            receiver_thread.start()

            sender_thread.join(timeout=20)
            receiver_thread.join(timeout=20)

            if not sender_error_queue.empty():
                self.fail(f"Sender thread raised an error: {sender_error_queue.get()}")
            if not receiver_error_queue.empty():
                self.fail(f"Receiver thread raised an error: {receiver_error_queue.get()}")

            if sender_thread.is_alive():
                self.fail("Sender thread did not complete within timeout.")
            if receiver_thread.is_alive():
                self.fail("Receiver thread did not complete within timeout.")

            self.assertIsNotNone(receiver.received_message)
            self.assertEqual(receiver.received_message, m1_text)
            self.assertNotIn(m0_text, receiver.received_message)

    def test_ot_connection_refused(self):
        with SuppressOutput():
            receiver = Receiver(host='127.0.0.1', port=50002)  # Try a port where no sender is running
            receiver.set_choice(0)

            # Expect ConnectionRefusedError
            with self.assertRaises(ConnectionRefusedError):
                receiver.start()


if __name__ == '__main__':
    unittest.main()
