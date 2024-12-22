import sys
import getopt
import hashlib
import logging

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from numpy.random import randint
from tqdm import trange

from qiskit import QuantumCircuit, transpile
from qiskit_aer import Aer

# some global variables
N = 100

class LevelDependentFormatter(logging.Formatter):
    FORMATS = {
        logging.DEBUG:    "\033[93m%(asctime)s [DEBUG]\t%(message)s\033[0m",
        logging.INFO:     "\033[33m%(asctime)s [INFO]\t\t%(message)s\033[0m",
        logging.WARNING:  "\033[31m%(asctime)s [WARNING]\t%(message)s\033[0m",
        logging.ERROR:    "\033[91m%(asctime)s [ERROR]\t%(message)s\033[0m",
        logging.CRITICAL: "\033[95m%(asctime)s [CRITICAL]\t%(message)s\033[0m",
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, self._fmt)
        formatter = logging.Formatter(log_fmt, datefmt=self.datefmt)
                
        return formatter.format(record)

def init_logging() -> logging.Logger:
    logging.getLogger().setLevel(logging.WARNING)
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    handler = logging.StreamHandler()
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(LevelDependentFormatter(datefmt="%H:%M:%S"))

    if logger.hasHandlers():
        logger.handlers.clear()

    logger.addHandler(handler)

    return logger

# class def
class Person:
    def __init__(self):
        self.n = N
        self._basis: list[int] = list(randint(2, size=self.n))
        self._bits: list[int] = []
        self._key: list[int] = []
        self._aes_key: bytes = b''

    def get_basis(self) -> list[int]:
        return self._basis

    def get_bits(self) -> list[int]:
        return self._bits

    def get_key(self) -> list[int]:
        return self._key

    def set_shared_key(self, other_basis: list[int]) -> None:
        self._key = []
        for i in range(self.n):
            if self._basis[i] == other_basis[i]:
                self._key.append(self._bits[i])
        self._aes_key = hashlib.md5(''.join(map(str, self._key)).encode()).digest()

    def regen_basis(self):
        self._basis: list[int] = list(randint(2, size=self.n))

    def encrypt(self, plaintext: bytes) -> bytes:
        cipher = AES.new(self._aes_key, AES.MODE_ECB)
        return cipher.encrypt(pad(plaintext, 16))

    def decrypt(self, ciphertext: bytes) -> bytes:
        cipher = AES.new(self._aes_key, AES.MODE_ECB)
        return unpad(cipher.decrypt(ciphertext), 16)

# qkd sender
class A(Person):
    def __init__(self) -> None:
        super().__init__()
        self._bits = list(randint(2, size=self.n))

    def encode(self) -> list[QuantumCircuit]:
        message: list[QuantumCircuit] = []
        for i in range(self.n):
            circuit = QuantumCircuit(1, 1)
            if self._basis[i] == 0:
                if self._bits[i] == 0:
                    pass
                else:
                    circuit.x(0)
            else:
                if self._bits[i] == 0:
                    circuit.h(0)
                else:
                    circuit.x(0)
                    circuit.h(0)
            circuit.barrier()
            message.append(circuit)
        return message

# qkd receiver
class B(Person):
    def measure(self, message: list[QuantumCircuit]) -> None:
        self._bits = []

        for i in trange(self.n):
            if self._basis[i] == 0:
                message[i].measure(0, 0)
            else:
                message[i].h(0)
                message[i].measure(0, 0)

            aer_sim = Aer.get_backend('aer_simulator')
            result = aer_sim.run(message[i], shots=1, memory=True).result()
            measured_bit = int(result.get_memory()[0])
            self._bits.append(measured_bit)
            message[i] = QuantumCircuit(1, 1)

            if measured_bit == 1:
                message[i].x(0)

def init(argv) -> logging.Logger: 
    logger = init_logging()

    try:
        opts, args = getopt.getopt(argv[1:], 
                                "v", ["verbose"])
    except getopt.GetoptError as err:
        print("\033[91mERROR]\t" + f"Getopt Error: {err}" + "\033[0m")
        sys.exit(-1)

    for opt, _ in opts:
        if opt in ("-v", "--verbose"):
            logger.setLevel(logging.DEBUG)
    
    return logger

def main(argv):
    logger = init(argv)

    alice = A()
    bob = B()
    eve = B()  # the eavesdropper

    logger.info("Opening Quantum Channel")
    message = alice.encode()
    bob.measure(message)

    logger.debug(f"Alice's basis\t: {''.join(map(str, alice.get_basis()))}")
    logger.debug(f"Bob's basis\t: {''.join(map(str, bob.get_basis()))}")
    
    alice.set_shared_key(bob.get_basis())
    bob.set_shared_key(alice.get_basis())

    msg = input(">> ")
    enc_msg = alice.encrypt(msg.encode())

    logger.debug("encrypted as: " + str(enc_msg))

    dec_msg = bob.decrypt(enc_msg)
    print("decrypted as: " + dec_msg.decode())

    logger.info("Closing Quantum Channel\n")

    logger.info("Regenerating Basis\n")
    alice.regen_basis()
    bob.regen_basis()

    logger.info("Opening Quantum Channel")
    message = alice.encode()
    # eavesdropper here
    eve.measure(message)
    bob.measure(message)

    logger.debug(f"Alice's basis\t: {''.join(map(str, alice.get_basis()))}")
    logger.debug(f"Eve's basis\t: {''.join(map(str, eve.get_basis()))}")
    logger.debug(f"Bob's basis\t: {''.join(map(str, bob.get_basis()))}")

    alice.set_shared_key(bob.get_basis())
    bob.set_shared_key(alice.get_basis())

    msg = input(">> ")

    enc_msg = alice.encrypt(msg.encode())
    print("encrypted as: " + str(enc_msg))

    try:
        dec_msg = bob.decrypt(enc_msg)
        print("decrypted as: " + dec_msg.decode() + "\n")
    except ValueError:
        logger.error("Eavesdropper detected!")
    finally:
        logger.info("Closing Quantum Channel\n")


if __name__ == "__main__":
    main(argv=sys.argv)
