import socket
import logging
import random
import json
from src.common.utils import serialize_data, deserialize_data, bytes_to_long, long_to_bytes
from src.common.crypto_utils import ElGamal, derive_shared_secret, decrypt_message_with_elgamal_shared_secret

# Configure logging for the receiver
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - Receiver - %(message)s')


class Receiver:
    def __init__(self, host='127.0.0.1', port=65432):
        """
        Initializes the Receiver for the Oblivious Transfer protocol.
        Args:
            host (str): The IP address of the Sender.
            port (int): The port number the Sender is listening on.
        """
        self.host = host
        self.port = port
        self.choice = None  # The index of the message to receive (0 or 1)
        self.p = None  # Prime modulus received from Sender
        self.g = None  # Generator received from Sender
        self.Y0 = None  # Sender's public key for M0
        self.Y1 = None  # Sender's public key for M1
        self.k = None  # Receiver's secret random value
        self.received_message = None  # The final decrypted message

        logging.info(f"Receiver initialized, ready to connect to {self.host}:{self.port}")

    def set_choice(self, choice_index):
        """
        Sets the index of the message the receiver wishes to obtain.
        Args:
            choice_index (int): 0 for M0, 1 for M1.
        """
        if choice_index not in [0, 1]:
            raise ValueError("Choice index must be either 0 or 1.")
        self.choice = choice_index
        logging.info(f"Receiver's choice set to receive message M{self.choice}")

    def start(self):
        """
        Connects to the Sender's socket server and executes the Oblivious Transfer protocol.
        """
        if self.choice is None:
            logging.error("Receiver's choice must be set before starting the protocol.")
            raise ValueError("Choice not set.")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                logging.info(f"Attempting to connect to Sender at {self.host}:{self.port}...")
                s.connect((self.host, self.port))
                logging.info(f"Connected to Sender at {self.host}:{self.port}")
                self._execute_protocol(s)
            except ConnectionRefusedError:
                logging.error("Connection refused. Make sure the Sender is running and listening.")
                raise
            except OSError as e:
                logging.error(f"Socket error: {e}")
                raise
            except Exception as e:
                logging.error(f"An unexpected error occurred in Receiver.start: {e}")
                raise

    def _execute_protocol(self, conn):
        """
        Executes the ElGamal-based 1-of-2 Oblivious Transfer protocol steps.
        Args:
            conn (socket.socket): The established socket connection to the Sender.
        """
        # Step 1: Receiver receives (p, g, Y0, Y1) from Sender
        received_data = conn.recv(4096)  # Adjust buffer size as needed
        if not received_data:
            logging.error("Sender disconnected or sent no data during initial parameters reception.")
            raise ConnectionError("Sender did not send initial parameters.")

        try:
            initial_params = deserialize_data(received_data)
            self.p = initial_params['p']
            self.g = initial_params['g']
            self.Y0 = initial_params['Y0']
            self.Y1 = initial_params['Y1']
            logging.info(
                f"Step 1: Received (p, g, Y0, Y1) from Sender. p (first few digits): {str(self.p)[:10]}..., g: {self.g}")
        except (json.JSONDecodeError, KeyError) as e:
            logging.error(f"Failed to deserialize or extract initial parameters: {e}")
            raise ValueError("Invalid initial parameters received.")

        # Step 2: Receiver computes K0, K1 based on choice and sends them to Sender
        # Generate receiver's random secret k
        # k should be from {1, ..., p-2}
        self.k = random.randint(1, self.p - 2)
        logging.debug(f"Receiver's private key (k): {self.k}")

        K0 = None
        K1 = None

        if self.choice == 0:
            # Bob wants M0: K0 = Y0^k mod p, K1 = g^k mod p
            K0 = derive_shared_secret(self.Y0, self.k, self.p)
            K1 = derive_shared_secret(self.g, self.k, self.p)
            logging.info(f"Receiver chose M0. Computed K0=Y0^k, K1=g^k.")
        elif self.choice == 1:
            # Bob wants M1: K0 = g^k mod p, K1 = Y1^k mod p
            K0 = derive_shared_secret(self.g, self.k, self.p)
            K1 = derive_shared_secret(self.Y1, self.k, self.p)
            logging.info(f"Receiver chose M1. Computed K0=g^k, K1=Y1^k.")

        receiver_keys = {
            'K0': K0,
            'K1': K1
        }
        conn.sendall(serialize_data(receiver_keys))
        logging.info("Step 2: Sent (K0, K1) to Sender.")

        # Step 3: Receiver receives (C0, C1) from Sender
        received_data = conn.recv(4096)  # Adjust buffer size as needed
        if not received_data:
            logging.error("Sender disconnected or sent no data during C0, C1 reception.")
            raise ConnectionError("Sender did not send C0, C1.")

        try:
            final_ciphertexts = deserialize_data(received_data)
            C0 = final_ciphertexts['C0']
            C1 = final_ciphertexts['C1']
            logging.info("Step 3: Received (C0, C1) from Sender.")
        except (json.JSONDecodeError, KeyError) as e:
            logging.error(f"Failed to deserialize or extract C0, C1: {e}")
            raise ValueError("Invalid data received for C0, C1.")

        # Step 4: Receiver decrypts the chosen message
        # Compute the decryption secret: S_b = g^k mod p (where b is the chosen index)
        # In our protocol, only one of the K_i values that Bob sent was g^k.
        # So, the decryption key for the chosen message is always g^k.
        decryption_secret = derive_shared_secret(self.g, self.k, self.p)
        logging.debug(f"Receiver's decryption secret (g^k): {decryption_secret}")

        chosen_ciphertext = C0 if self.choice == 0 else C1

        try:
            decrypted_int_message = decrypt_message_with_elgamal_shared_secret(
                chosen_ciphertext, decryption_secret, self.p
            )
            # Convert the integer message back to bytes and then to string
            self.received_message = long_to_bytes(decrypted_int_message).decode('utf-8')
            logging.info(f"Step 4: Successfully decrypted message M{self.choice}.")
            logging.info(f"Received message: '{self.received_message}'")
        except Exception as e:
            logging.error(f"Error during decryption: {e}")
            self.received_message = f"Decryption Failed: {e}"
            raise


# Example usage (for testing purposes, not part of the main GUI flow):
if __name__ == '__main__':
    logging.info("--- Testing Receiver.py ---")

    # This block would only work if you have a sender running and listening.
    # For proper testing, launch the sender script and then this receiver script separately.

    test_receiver = Receiver()
    # User input for choice, or hardcode for testing
    user_choice = input("Enter your choice (0 for M0, 1 for M1): ")
    try:
        test_receiver.set_choice(int(user_choice))
    except ValueError:
        logging.error("Invalid input for choice. Please enter 0 or 1.")
        exit(1)

    print(
        f"\nReceiver is trying to connect to {test_receiver.host}:{test_receiver.port} to get M{test_receiver.choice}...")

    try:
        test_receiver.start()
        print(f"Receiver finished. The message received is: '{test_receiver.received_message}'")
    except Exception as e:
        logging.error(f"Receiver test failed: {e}")
