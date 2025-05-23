import socket
import logging
import random
import json
from src.common.utils import serialize_data, deserialize_data, long_to_bytes, bytes_to_long
from src.common.crypto_utils import ElGamal, derive_shared_secret, get_inverse_modulo_order, \
    encrypt_message_with_elgamal_shared_secret

# Configure logging for the sender
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - Sender - %(message)s')


class Sender:
    def __init__(self, host='127.0.0.1', port=65432, bit_length=1024):
        self.host = host
        self.port = port
        self.bit_length = bit_length
        self.p = None
        self.g = None
        self.x0 = None
        self.x1 = None
        self.Y0 = None
        self.Y1 = None
        self.messages = [None, None]
        self.elgamal = None  # Initialize as None, will be set after p, g are known
        logging.info(f"Sender initialized on {self.host}:{self.port} with {self.bit_length}-bit security.")

    def set_messages(self, m0, m1):
        self.messages[0] = bytes_to_long(m0.encode('utf-8'))
        self.messages[1] = bytes_to_long(m1.encode('utf-8'))
        logging.info(f"Messages set. M0: '{m0}', M1: '{m1}'. Converted to integers.")

    def _generate_keys(self):
        logging.info("Generating ElGamal parameters (p, g) and sender keys...")
        # FIX: Directly call generate_elgamal_parameters without an ElGamal instance,
        # or make it a static method in ElGamal if it truly doesn't depend on self.p/self.g
        # For now, let's make generate_elgamal_parameters a static method in ElGamal
        # or change it to be a standalone function as in my previous suggestion.
        # Given your current structure, let's assume it should be static/classmethod or refactored.
        # Easiest immediate fix: import generate_elgamal_parameters as a standalone function
        # from common.crypto_utils if that's how you want to use it.
        # Or if it must be a class method and your ElGamal __init__ needs valid p,g:
        # A common pattern is to make generate_elgamal_parameters a standalone function
        # that returns p, g. Then you initialize ElGamal(p, g).

        # Option A (preferred for clean separation): Move generate_elgamal_parameters out of ElGamal class
        # (This would mean making changes in crypto_utils.py as well)
        # self.p, self.g = generate_elgamal_parameters(self.bit_length)

        # Option B (if generate_elgamal_parameters must stay a method of ElGamal and ElGamal.__init__ is strict)
        # The best way to handle this with your current ElGamal class is to defer its instantiation
        # until after p and g are generated, and generate p and g using a mechanism that doesn't
        # require ElGamal.__init__ to be called with dummy values.
        # Let's assume generate_elgamal_parameters becomes a standalone function for now.
        # I'll update crypto_utils.py below to reflect this.

        # New approach: Use a standalone function for parameter generation
        from src.common.crypto_utils import generate_elgamal_parameters_standalone  # Will add this to crypto_utils.py
        self.p, self.g = generate_elgamal_parameters_standalone(self.bit_length)

        self.elgamal = ElGamal(self.p, self.g)  # Now ElGamal is initialized with valid p,g

        self.x0 = self.elgamal.generate_private_key()
        self.x1 = self.elgamal.generate_private_key()

        self.Y0 = self.elgamal.compute_public_key(self.x0)
        self.Y1 = self.elgamal.compute_public_key(self.x1)
        logging.info("Sender keys and public values (Y0, Y1) generated.")

    def start(self):
        self._generate_keys()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((self.host, self.port))
                s.listen()
                logging.info(f"Sender listening on {self.host}:{self.port}...")
                conn, addr = s.accept()
                with conn:
                    logging.info(f"Connection established with Receiver from {addr}")
                    self._execute_protocol(conn)
            except OSError as e:
                logging.error(f"Socket error: {e}. Ensure the port is not in use.")
                raise
            except Exception as e:
                logging.error(f"An unexpected error occurred in Sender.start: {e}")
                raise

    def _execute_protocol(self, conn):
        initial_params = {
            'p': self.p,
            'g': self.g,
            'Y0': self.Y0,
            'Y1': self.Y1
        }
        conn.sendall(serialize_data(initial_params))
        logging.info("Step 1: Sent (p, g, Y0, Y1) to Receiver.")

        received_data = conn.recv(4096)
        if not received_data:
            logging.error("Receiver disconnected or sent no data during K0, K1 reception.")
            raise ConnectionError("Receiver did not send K0, K1.")

        try:
            receiver_keys = deserialize_data(received_data)
            K0 = receiver_keys['K0']
            K1 = receiver_keys['K1']
            logging.info("Step 2: Received (K0, K1) from Receiver.")
        except (json.JSONDecodeError, KeyError) as e:
            logging.error(f"Failed to deserialize or extract K0, K1: {e}")
            raise ValueError("Invalid data received for K0, K1.")

        try:
            x0_inv = get_inverse_modulo_order(self.x0, self.p - 1)
            x1_inv = get_inverse_modulo_order(self.x1, self.p - 1)
            logging.debug(f"Computed x0_inv: {x0_inv}, x1_inv: {x1_inv}")
        except ValueError as e:
            logging.error(f"Error computing modular inverse of x0 or x1: {e}")
            raise

        S0 = derive_shared_secret(K0, x0_inv, self.p)
        S1 = derive_shared_secret(K1, x1_inv, self.p)
        logging.info("Step 3 (a): Computed S0 and S1.")

        # Ensure messages are smaller than p for direct modular arithmetic (important for string conversion)
        # If they are larger, you'd need a KDF on S0/S1 and then AES encryption, or chunk the message.
        # For now, let's add a check and truncate if necessary for this basic ElGamal scheme.
        message0_to_encrypt = self.messages[0] % self.p if self.messages[0] >= self.p else self.messages[0]
        message1_to_encrypt = self.messages[1] % self.p if self.messages[1] >= self.p else self.messages[1]

        C0 = encrypt_message_with_elgamal_shared_secret(message0_to_encrypt, S0, self.p)
        C1 = encrypt_message_with_elgamal_shared_secret(message1_to_encrypt, S1, self.p)
        logging.info("Step 3 (b): Computed C0 and C1 (encrypted messages).")

        final_ciphertexts = {
            'C0': C0,
            'C1': C1
        }
        conn.sendall(serialize_data(final_ciphertexts))
        logging.info("Step 4: Sent (C0, C1) to Receiver. Protocol finished.")


if __name__ == '__main__':
    logging.info("--- Testing Sender.py ---")
    test_sender = Sender()
    test_sender.set_messages("Secret Message 0", "Secret Message 1")
    print("\nTo test, please run src/receiver/receiver.py in another terminal.")
    print(f"Sender is trying to start on {test_sender.host}:{test_sender.port}...")
    try:
        test_sender.start()
        print("Sender finished.")
    except Exception as e:
        logging.error(f"Sender test failed: {e}")