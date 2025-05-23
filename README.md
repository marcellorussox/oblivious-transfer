# Oblivious Transfer Protocol Implementation

## Project Overview

This project implements a **1-of-2 Oblivious Transfer (OT) protocol**, a fundamental cryptographic primitive that allows a sender to transmit one of two messages to a receiver, such that the receiver obtains only the chosen message without learning anything about the other message, and the sender remains oblivious to which message was chosen.

The implementation adheres to the following guidelines:
* **Two or More Participants:** The sender and receiver are implemented as independent processes that communicate via network sockets.
* **Arbitrary-Precision Integers:** Public-key cryptography operations utilize arbitrary-precision integers, supporting numbers with 100 digits or more, as required for cryptographic security.
* **Cryptographic Primitives:** Third-party cryptographic libraries are used for underlying cryptographic operations, ensuring robust and standard-compliant implementations.

## Protocol Chosen: ElGamal-based 1-of-2 Oblivious Transfer

We've chosen an ElGamal-based approach for the 1-of-2 Oblivious Transfer. This protocol leverages the security of the ElGamal encryption scheme and the Diffie-Hellman key exchange for its oblivious properties.

### Brief Protocol Description:

1.  **Setup:** A large prime $p$ and a generator $g$ for a cyclic group are agreed upon.
2.  **Sender (Alice) Initialization:**
    * Alice possesses two messages, $M_0$ and $M_1$.
    * Alice generates two random secret values, $x_0, x_1 \in \{1, \dots, p-1\}$.
    * Alice computes two public keys, $Y_0 = g^{x_0} \pmod p$ and $Y_1 = g^{x_1} \pmod p$.
    * Alice sends $Y_0$ and $Y_1$ to Bob.
3.  **Receiver (Bob) Initialization:**
    * Bob wants to receive $M_b$ where $b \in \{0, 1\}$.
    * Bob chooses a random secret value $k \in \{1, \dots, p-1\}$.
    * If Bob wants $M_0$, he computes $K_0 = Y_0^k \pmod p$ and $K_1 = g^k \pmod p$.
    * If Bob wants $M_1$, he computes $K_0 = g^k \pmod p$ and $K_1 = Y_1^k \pmod p$.
    * Bob sends $K_0$ and $K_1$ to Alice.
4.  **Sender (Alice) Encryption:**
    * Alice computes two shared secrets:
        * $S_0 = K_0^{x_0^{-1}} \pmod p$ (where $x_0^{-1}$ is the modular multiplicative inverse of $x_0 \pmod {p-1}$)
        * $S_1 = K_1^{x_1^{-1}} \pmod p$ (where $x_1^{-1}$ is the modular multiplicative inverse of $x_1 \pmod {p-1}$)
    * Alice then computes the encrypted messages:
        * $C_0 = M_0 \cdot S_0 \pmod p$
        * $C_1 = M_1 \cdot S_1 \pmod p$
    * Alice sends $C_0$ and $C_1$ to Bob.
5.  **Receiver (Bob) Decryption:**
    * Bob computes his decryption key $S_b = g^k \pmod p$.
    * Bob can then decrypt his chosen message $M_b = C_b \cdot S_b^{-1} \pmod p$.

This protocol ensures that Bob only learns $M_b$ because only one of the $S_i$ values he receives can be used to decrypt his chosen message, and he cannot compute the other $S_j$ without knowing Alice's secret $x_j$. Alice, on the other hand, cannot determine which $K_i$ corresponds to Bob's $g^k$ and thus remains oblivious to Bob's choice.

## Project Structure

```
oblivious_transfer_project/
├── src/
│   ├── common/
│   │   ├── __init__.py
│   │   ├── utils.py                 # Utility functions (e.g., for large prime generation)
│   │   └── crypto_utils.py          # Cryptographic primitives and helper functions
│   ├── sender/
│   │   ├── __init__.py
│   │   ├── sender.py                # Core Sender logic
│   │   └── sender_gui.py            # Sender GUI (optional, but recommended)
│   ├── receiver/
│   │   ├── __init__.py
│   │   ├── receiver.py              # Core Receiver logic
│   │   └── receiver_gui.py          # Receiver GUI (optional, but recommended)
│   └── main.py                      # Main script to run Sender/Receiver processes
├── tests/
│   ├── test_protocol.py             # Unit and integration tests
├── requirements.txt                 # Project dependencies
└── .gitignore                       # Git ignore file
```

## Setup and Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/marcellorussox/oblivious-transfer.git](https://github.com/marcellorussox/oblivious-transfer.git)
    cd oblivious_transfer_project
    ```

2.  **Create and activate a virtual environment (recommended):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On macOS/Linux
    # venv\Scripts\activate   # On Windows
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Running the Project

The sender and receiver are independent processes and must be run in separate terminal windows.

1.  **Start the Sender:**
    In your first terminal:
    ```bash
    python src/main.py
    # Then choose option 1 or 3
    ```
    Alternatively, for direct GUI launch (if GUI is implemented):
    ```bash
    python src/sender/sender_gui.py
    ```

2.  **Start the Receiver:**
    In your second terminal:
    ```bash
    python src/main.py
    # Then choose option 2 or 3
    ```
    Alternatively, for direct GUI launch (if GUI is implemented):
    ```bash
    python src/receiver/receiver_gui.py
    ```

Follow the instructions in the respective GUI windows or console prompts to execute the Oblivious Transfer protocol.

## Requirements

* Python 3.8+
* See `requirements.txt` for specific Python library dependencies.

## Contributing

Feel free to open issues or submit pull requests.
