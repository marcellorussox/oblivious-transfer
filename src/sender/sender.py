import socket
import logging
import random
from src.common.utils import get_large_prime, serialize_data, deserialize_data, long_to_bytes, bytes_to_long
from src.common.crypto_utils import ElGamal, derive_shared_secret, get_inverse_modulo_order, \
    encrypt_message_with_elgamal_shared_secret

# Configure logging for the sender
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - Sender - %(message)s')


class Sender:
    def __init__(self, host='127.0.0.1', port=65432, bit_length=1024):
        """
        Initializes the Sender for the Oblivious Transfer protocol.
        Args:
            host (str): The IP address to bind the socket to.
            port (int): The port number to listen on.
            bit_length (int): The bit length for the ElGamal prime 'p'.
        """
        self.host = host
        self.port = port
        self.bit_length = bit_length
        self.p = None  # Large prime modulus
        self.g = None  # Generator
        self.x0 = None  # Sender's secret key for M0
        self.x1 = None  # Sender's secret key for M1
        self.Y0 = None  # Sender's public key derived from x0
        self.Y1 = None  # Sender's public key derived from x1
        self.messages = [None, None]  # [M0, M1]
        self.elgamal = None
        logging.info(f"Sender initialized on {self.host}:{self.port} with {self.bit_length}-bit security.")

    def set_messages(self, m0, m1):
        """
        Sets the two messages (M0 and M1) that the sender wants to offer.
        Messages will be converted to integers for cryptographic operations.
        """
        # It's important to convert messages to integers for ElGamal operations.
        # A simple way is to encode them as bytes and then convert to long.
        # For demonstration, we'll ensure they fit within the modulus 'p'.
        # A more robust solution might involve symmetric encryption of messages
        # after deriving a shared key through the OT.
        self.messages[0] = bytes_to_long(m0.encode('utf-8'))
        self.messages[1] = bytes_to_long(m1.encode('utf-8'))
        logging.info(f"Messages set. M0: '{m0}', M1: '{m1}'. Converted to integers.")

    def _generate_keys(self):
        """
        Generates ElGamal parameters (p, g) and the sender's private keys (x0, x1)
        and corresponding public keys (Y0, Y1).
        """
        logging.info("Generating ElGamal parameters (p, g) and sender keys...")
        elgamal_instance = ElGamal(1, 1)  # Dummy instance to use generate_elgamal_parameters
        self.p, self.g = elgamal_instance.generate_elgamal_parameters(self.bit_length)

        self.elgamal = ElGamal(self.p, self.g)  # Initialize ElGamal with actual parameters

        self.x0 = self.elgamal.generate_private_key()
        self.x1 = self.elgamal.generate_private_key()

        self.Y0 = self.elgamal.compute_public_key(self.x0)
        self.Y1 = self.elgamal.compute_public_key(self.x1)
        logging.info("Sender keys and public values (Y0, Y1) generated.")

    def start(self):
        """
        Starts the sender's socket server and waits for the receiver to connect,
        then executes the Oblivious Transfer protocol.
        """
        self._generate_keys()  # Generate cryptographic parameters and keys

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
        """
        Executes the ElGamal-based 1-of-2 Oblivious Transfer protocol steps.
        Args:
            conn (socket.socket): The established socket connection to the Receiver.
        """
        # Step 1: Sender sends (p, g, Y0, Y1) to Receiver
        initial_params = {
            'p': self.p,
            'g': self.g,
            'Y0': self.Y0,
            'Y1': self.Y1
        }
        conn.sendall(serialize_data(initial_params))
        logging.info("Step 1: Sent (p, g, Y0, Y1) to Receiver.")

        # Step 2: Receiver sends (K0, K1) to Sender
        received_data = conn.recv(4096)  # Adjust buffer size as needed
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

        # Step 3: Sender computes S0, S1 and encrypted messages C0, C1
        # Compute modular inverse of x0 and x1 modulo (p-1)
        # Note: The order of the group (Z_p)^* is p-1. So the exponents are modulo p-1.
        try:
            x0_inv = get_inverse_modulo_order(self.x0, self.p - 1)
            x1_inv = get_inverse_modulo_order(self.x1, self.p - 1)
            logging.debug(f"Computed x0_inv: {x0_inv}, x1_inv: {x1_inv}")
        except ValueError as e:
            logging.error(f"Error computing modular inverse of x0 or x1: {e}")
            raise

        # Compute S0 = K0^(x0_inv) mod p
        # Compute S1 = K1^(x1_inv) mod p
        S0 = derive_shared_secret(K0, x0_inv, self.p)
        S1 = derive_shared_secret(K1, x1_inv, self.p)
        logging.info("Step 3 (a): Computed S0 and S1.")

        # Encrypt messages: C0 = M0 * S0 mod p, C1 = M1 * S1 mod p
        # Ensure messages are within the group range before encryption if they are not already
        C0 = encrypt_message_with_elgamal_shared_secret(self.messages[0], S0, self.p)
        C1 = encrypt_message_with_elgamal_shared_secret(self.messages[1], S1, self.p)
        logging.info("Step 3 (b): Computed C0 and C1 (encrypted messages).")

        # Step 4: Sender sends (C0, C1) to Receiver
        final_ciphertexts = {
            'C0': C0,
            'C1': C1
        }
        conn.sendall(serialize_data(final_ciphertexts))
        logging.info("Step 4: Sent (C0, C1) to Receiver. Protocol finished.")


# Example usage (for testing purposes, not part of the main GUI flow):
if __name__ == '__main__':
    logging.info("--- Testing Sender.py ---")

    # You'd typically run this in a separate process or thread from the receiver.
    # For a quick test, you might use multiprocessing.

    # Simple direct test (without separate process/GUI):
    # This block would only work if you have a dummy receiver that connects and sends data.
    # For proper testing, launch this script and then the receiver script separately.

    test_sender = Sender()
    test_sender.set_messages("Secret Message 0", "Secret Message 1")

    print("\nTo test, please run src/receiver/receiver.py in another terminal.")
    print(f"Sender is trying to start on {test_sender.host}:{test_sender.port}...")

    try:
        test_sender.start()
        print("Sender finished.")
    except Exception as e:
        logging.error(f"Sender test failed: {e}")