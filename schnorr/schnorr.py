import os
from binascii import hexlify, unhexlify
from hashlib import sha256
from .groups import Params3072, _Params

# Exceptions


class ZKError(Exception):
    pass


class OnlyCallStartOnce(ZKError):
    """the function may only be called once."""
    # Re-using a ZK instance is likely to reveal the witness known to the prover.


class WrongSide(ZKError):
    """The function is called on a wrong side: I was
    expecting the opposite side."""


class InvalidPreSignatureError(ZKError):
    pass


class InvalidSignatureError(ZKError):
    pass


class WrongGroupError(ZKError):
    pass


class OnlyPresignOnce(ZKError):
    pass


SideProver = b"P"
SideVerifier = b"V"

DefaultParams = Params3072


#
# Example of usage:  hash(a,b)
#
def hash(*args):
    h = sha256()
    for arg in args:
        h.update(arg)
    digest = h.digest()
    # a hack to fit into Zq
    digest_modified = bytearray(digest)
    digest_modified[0] = 0
    digest_modified[-1] = 0
    return bytes(digest_modified)


class Schnorr_Exchange:
    """
    This class manages both sides of the exchange protocol.
    """

    def __init__(
        self,
        side,
        params=DefaultParams,
        entropy_f=os.urandom,
    ):
        self.params = params
        self.side = side
        self.entropy_f = entropy_f
        self._gen_stmt_started = False
        self._presig_sent = False

    def generate_statement(self):
        if self.side != SideProver:
            raise WrongSide('Only Alice can call generate_statement')
        if self._gen_stmt_started:
            raise OnlyCallStartOnce("generate_statement() can only be called once")
        self._gen_stmt_started = True

        g = self.params.group

        # Setup a public/private key, return the public key so others can have it
        self.x = g.random_exponent(self.entropy_f)
        self.X = g.Base.exp(self.x)
        return self.X.to_bytes()

    def set_statement(self, msg_statement):
        """Bob setups its known parameters based on Alice outputs"""
        if self.side != SideVerifier:
            raise WrongSide('Only Bob can call set_statement')
        g = self.params.group
        self.X = g.bytes_to_element(msg_statement)

        # Setup witness and statement for the discrete log
        self.d = g.random_exponent(self.entropy_f)
        self.DLog_statement = g.Base.exp(self.d)  # D in the protocol
        self.message = "This is a message Bob wants to be signed by Alice"

        return (self.message, self.DLog_statement)

    def get_dlog_statement_witness(self):
        """Helper function to retrieve the witness from Bob"""
        if self.side != SideVerifier:
            raise WrongSide('Only Bob can show the witness it knows')
        return self.params.group.exponent_to_bytes(self.d)

    def pre_sign_message(self, message, DLog_statement):
        """Alice receives a message to sign in exchange of the discrete log of DLog_statement"""
        if self.side != SideProver:
            raise WrongSide('Only Alice can call pre_sign_message')
        if self._presig_sent:
            # Technically Alice should check that she did not send a presig for the current D
            raise OnlyPresignOnce('Alice has already sent a pre-signature')

        g = self.params.group

        # BEGIN YOUR CODE SNIPPET HERE

        # END YOUR CODE SNIPPET HERE

        # Send back (~c, ~s) as bytes so they can transit over a network
        return g.exponent_to_bytes(c_tilde), g.exponent_to_bytes(s_tilde)

    def sign_message(self, pre_signature):
        """Bob receives a pre-signature and publishes the related signature.
        This function raises InvalidPreSignatureError in case of invalid hash"""
        if self.side != SideVerifier:
            raise WrongSide('Only Bob can call sign_message')

        g = self.params.group
        c_tilde = g.bytes_to_exponent(pre_signature[0])
        s_tilde = g.bytes_to_exponent(pre_signature[1])

        # BEGIN YOUR CODE SNIPPET HERE

        # END YOUR CODE SNIPPET HERE

        return (g.exponent_to_bytes(c), g.exponent_to_bytes(s))

    def extract_witness(self, signature):
        """Alice receives a signature and extracts the witness of the DLog statement
        This function raises the exception InvalidSignatureError in case of invalid hash"""
        if self.side != SideProver:
            raise WrongSide('Only Alice can call extract_witness')

        g = self.params.group
        c = g.bytes_to_exponent(signature[0])
        s = g.bytes_to_exponent(signature[1])

        # BEGIN YOUR CODE SNIPPET HERE

        # END YOUR CODE SNIPPET HERE
        return g.exponent_to_bytes(d)
