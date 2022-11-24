import secrets  # for generating hex
import binascii  # for conversion between Hexa and bytes
import hashlib  # for SHA256 computation
import unicodedata
from passlib.context import CryptContext
pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


def password_hash(password):
    return pwd_context.hash(password)


def determine_seed_by_entropy(entropy):
    data = entropy.strip()  # cleaning of data if there are dashes
    data = binascii.unhexlify(data)  # the binary data of hexadecimal

    if len(data) not in [16, 20, 24, 28, 32]:
        raise ValueError(
            "Data length should be one of the following: [16, 20, 24, 28, 32], but it is not (%d)." % len(
                data))
    h = hashlib.sha256(data).hexdigest()
    b = bin(int(binascii.hexlify(data), 16))[2:].zfill(
        len(data)*8) + bin(int(h, 16))[2:].zfill(256)[: len(data) * 8//32]
    seed = []
    for i in range(len(b)//11):
        indx = int(b[11*i:11*(i+1)], 2)
        seed.append(BIP39().get_wordlist()[indx])
    return seed


class BIP39:
    def __init__(self):
        with open('wordlist.txt', 'r') as f:
            self.wordlist = f.read().splitlines()

    @staticmethod
    def generate_entropy():
        return secrets.token_hex(16)

    @staticmethod
    def generate_phrase(entropy):
        data = entropy.strip()
        data = binascii.unhexlify(data)
        h = hashlib.sha256(data).hexdigest()
        # print("hexadecimal: %s" % h)
        b = bin(int(binascii.hexlify(data), 16))[2:].zfill(
            len(data)*8) + bin(int(h, 16))[2:].zfill(256)[: len(data) * 8//32]
        # print("binary: %s" % b)
        seed = []
        with open('wordlist.txt', 'r') as f:
            wordlist = f.read().splitlines()
        for i in range(len(b)//11):
            indx = int(b[11*i:11*(i+1)], 2)
            seed.append(wordlist[indx])
        return seed

    def verify_entropy(self, plain, hashed):
        return pwd_context.verify(plain, hashed)

    def mneumonic_to_entropy(self, mneumonic):
        mneumonic = mneumonic.strip()
        mneumonic = mneumonic.split(' ')

        binary = []
        for i in range(len(mneumonic)):
            binary.append(self.wordlist.index(mneumonic[i]))
        for i in range(len(binary)):
            binary[i] = bin(binary[i])[2:].zfill(11)
        # print(binary)
        binary = ''.join(binary)
        entropy = str('%0*x' % ((len(binary) + 3) // 4, int(binary, 2)))[:-1]
        return entropy

    def verify_entropy_and_seed(self, user_seed, hashed_entropy):
        if len(user_seed.split(' ')) != 12:
            # Seed should be 12-words long, but it is not.
            return False
        for word in user_seed.split(' '):
            if word not in self.wordlist:
                # Seed contains an invalid word.
                return False
        entropy = self.mneumonic_to_entropy(user_seed)
        return self.verify_entropy(entropy, hashed_entropy)

    def phrase_to_seed(self, user_seed):
        normalized_mnemonic = unicodedata.normalize("NFKD", user_seed)
        password = ""
        normalized_passphrase = unicodedata.normalize("NFKD", password)

        passphrase = "mnemonic" + normalized_passphrase
        mnemonic = normalized_mnemonic.encode("utf-8")
        passphrase = passphrase.encode("utf-8")

        bin_seed = hashlib.pbkdf2_hmac("sha512", mnemonic, passphrase, 2048)
        return binascii.hexlify(bin_seed[:64]).decode("utf-8")


# print(BIP39.generate_entropy())

# print(BIP39().generate_phrase('a35e76b8ac006e60f5a82bd25e155c97'))

# for _ in range(5):
#     print(BIP39().generate_phrase())
#     print('\n')


# Assuming this is the entropy from the database.
# entropy = '9ed52bd6875de3318147a6ade56ad610'
# hashed_entropy = '$2b$12$SI7Vha2SK4jOknqoeTWRFuJxo9iNaaIz.xstkiIc/ohelhddSsVY2'
# user_seed = 'paddle power volcano attitude taste occur agree visit pupil clip remain canvas'
# print(entropy)
# print(BIP39().verify_entropy_and_seed(user_seed, hashed_entropy))

# entropy_data = ['f63e6f426c7e7e244b57d7e906d41ad6',
#                 '5a7110abc08a562d8e2a9e25045e5546',
#                 '332f302fdeb534fb33add2bb02e69cd5',
#                 '5691eb2d0a33bf9c355ebcb91d7aff81',
#                 '2beb9efe09a26d460ac45b337d98eb81']
# hashed_entropy = ['$2b$12$qqua5Z.E3ZW38Peh2AFhHOlqnTPDT4Re3efJifFYDaqlIufpjhDu6',
#                   '$2b$12$yrA2oRlwwbqUHfXaqUBBseBfKoQFODd3eeb628PfhElO6dH6JdLbG',
#                   '$2b$12$pbBzgVygbMQOud3Yi7SKZuJ1wqUJQl7n7WP97kqfV4BiZvny8viSW',
#                   '$2b$12$8nNnJudOV9tGOwjGO.llFuHC43OrK9DGdwXtyQJK8AFzbBrMVOHvy',
#                   '$2b$12$8rn0qd80hQEsoNok6YqxAO/3nq2.liTw.pCPIjSIWZ9b1NVJ1Ye0O']

# for x in range(10):
#     test_data = BIP39().generate_phrase()
#     hshd_ent = password_hash(test_data['entropy'])
#     seed = " ".join(determine_seed_by_entropy(test_data['entropy']))
#     print("Entropy: %s" % test_data['entropy'])
#     print("Hashed: %s" % hshd_ent)
#     print("Seed: %s" % test_data['seed'])
#     print("Verify:", BIP39().verify_entropy_and_seed(
#         " ".join(test_data['seed']), hshd_ent))
#     print('')


entropy = "cbd562db849985e6d1bd88501287f692"
hashed = password_hash(entropy)
print("Entropy: %s" % entropy)
seed = BIP39().generate_phrase(entropy)
print("seed: %s" % " ".join(seed))
print("Hashed: %s" % hashed)
print("Verify:", BIP39().verify_entropy_and_seed(" ".join(seed), hashed))
print("BIP39 Seed: %s" % BIP39().phrase_to_seed(" ".join(seed)))
