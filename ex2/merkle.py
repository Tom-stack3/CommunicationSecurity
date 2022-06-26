import base64
import hashlib

import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key


def hash(data):
    if isinstance(data, str):
        data = data.encode('utf-8')

    return hashlib.sha256(data).hexdigest()[:4]


class BinaryTreeNode:
    def __init__(self, key):
        self.key = key
        self.left = None
        self.right = None
        self.parent = None


class MerkleTree:
    def __init__(self, keys=None):
        if keys is None:
            keys = []

        self.root = None
        self.leafs = [BinaryTreeNode(hash(key)) for key in keys]
        if keys:
            self.build_tree()

    def build_tree(self):
        # build the tree
        data = self.leafs

        # While the tree is incomplete (there is no root node).
        while len(data) > 1:
            # For each pair of nodes, create a new node with the hash of the two nodes.
            i = 0
            while i < len(data) - 1:
                # Create a new node.
                node = BinaryTreeNode(hash(data[i].key.encode() + data[i + 1].key.encode()))
                # Set the left and right children of the new node to the two children.
                node.left = data[i]
                node.right = data[i + 1]
                # Set the parent of the two children to the new node.
                data[i].parent = node
                data[i + 1].parent = node
                # Add the new node to the list instead of the two children.
                data = data[:i] + [node] + data[i + 2:]
                i += 1

        self.root = data[0]

    def add_leaf(self, key):
        # add a leaf to the tree
        self.leafs.append(BinaryTreeNode(hash(key)))
        self.build_tree()

    def get_root(self):
        return self.root.key if self.root else ""

    def get_proof(self, index):
        node = self.leafs[index]
        proof = []
        # while the node is not the root
        while node.parent is not None:
            # if the node is the left child
            if node.parent.left is node:
                proof.append("1" + node.parent.right.key)
            else:
                proof.append("0" + node.parent.left.key)
            node = node.parent
        return proof

    @staticmethod
    def verify_proof(proof, root):
        # verify the proof
        while len(proof) > 1:
            a = proof[0]
            db, b = proof[1][0], proof[1][1:]
            if db == "1":
                proof = [hash(a + b)] + proof[2:]
            else:
                proof = [hash(b + a)] + proof[2:]

        return proof[0] == root

    @staticmethod
    def generate_rsa_keys():
        # generate a public and private key

        # generate a private key
        private_key = rsa.generate_private_key(public_exponent=65537,
                                               key_size=2048,
                                               backend=default_backend())
        # get the public key
        public_key = private_key.public_key()

        # get the private key in PEM format
        private_key_bytes = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                      format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                      encryption_algorithm=serialization.NoEncryption())
        # get the public key in PEM format
        public_key_bytes = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                   format=serialization.PublicFormat.SubjectPublicKeyInfo)

        return private_key_bytes.decode(), public_key_bytes.decode()

    @staticmethod
    def sign(message, private_key):
        # Load the private key.
        private_key = load_pem_private_key(private_key.encode(), password=None, backend=default_backend())
        # Sign the message.
        signature = private_key.sign(message.encode(),
                                     padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                     hashes.SHA256())
        return base64.b64encode(signature).decode()

    @staticmethod
    def verify(message, signature, public_key):
        # Load the public key.
        public_key = load_pem_public_key(public_key.encode(), backend=default_backend())
        try:

            public_key.verify(base64.b64decode(signature.encode()), message.encode(),
                              padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                              hashes.SHA256())
        except cryptography.exceptions.InvalidSignature:
            return False
        else:
            return True


def main():
    tree = MerkleTree()
    while True:
        try:
            command = input()
            option, *args = command.split(" ", maxsplit=1)
            if args:
                args = args[0]
            if option == "1":
                tree.add_leaf(args)
            elif option == "2":
                print(tree.get_root())
            elif option == "3":
                print(tree.get_root(), ' '.join(tree.get_proof(int(args))))
            elif option == "4":
                args = args.split(" ")
                print(MerkleTree.verify_proof([hash(args[0])] + args[2:], args[1]))
            elif option == "5":
                print("\n".join(MerkleTree.generate_rsa_keys()))
            elif option == "6":
                while not args.endswith("-----END RSA PRIVATE KEY-----"):
                    args += "\n" + input()
                input()
                print(MerkleTree.sign(tree.get_root(), args))
            elif option == "7":
                while "-----END PUBLIC KEY-----" not in args:
                    args += "\n" + input()
                input()
                key = args
                args = input()
                signature, message = args.rsplit(" ", maxsplit=1)
                print(MerkleTree.verify(message, signature, key))
        except:
            print()


if __name__ == "__main__":
    main()
