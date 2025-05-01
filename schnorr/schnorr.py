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

        # normalize to bytes
        msg = message if isinstance(message, (bytes, bytearray)) else message.encode()
        D_bytes = DLog_statement.to_bytes()

        # pick Alice’s ephemeral r and compute A = g^r
        r = g.random_exponent(self.entropy_f)
        A = g.Base.exp(r)

        # compute challenge c̃ = H(X || D || A || m)
        c_tilde_bytes = hash(self.X.to_bytes(), D_bytes, A.to_bytes(), msg)
        c_tilde = g.bytes_to_exponent(c_tilde_bytes)

        # get group order
        order = getattr(g, 'order', getattr(g, 'q', None))
        if order is None:
            raise WrongGroupError("group has no order/q attribute")

        # compute s̃ = r + c̃·x  (mod order)
        s_tilde = (r + c_tilde * self.x) % order

        # stash for later
        self.c_tilde = c_tilde
        self.s_tilde = s_tilde
        self.message_bytes = msg
        self.D_bytes = D_bytes
        self._presig_sent = True

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
        # re‐compute A = g^{s̃}·X^{−c̃}
        order = getattr(g, 'order', getattr(g, 'q', None))
        if order is None:
            raise WrongGroupError("group has no order/q attribute")

        A = g.Base.exp(s_tilde) * self.X.exp(-c_tilde)

        # verify the pre‐signature: c̃ == H(X || D || A || m)
        c_check = g.bytes_to_exponent(
            hash(self.X.to_bytes(), self.D_bytes, A.to_bytes(), self.message_bytes)
        )
        if c_check != c_tilde:
            raise InvalidPreSignatureError("pre-signature hash mismatch")

        # derive a fresh challenge c = H(X || D || A || m || b'final')
        c_bytes = hash(self.X.to_bytes(), self.D_bytes, A.to_bytes(), self.message_bytes, b'final')
        c = g.bytes_to_exponent(c_bytes)

        # Bob’s “response” s = d·c̃ + c  (mod order)
        s = (self.d * c_tilde + c) % order

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
        order = getattr(g, 'order', getattr(g, 'q', None))
        if order is None:
            raise WrongGroupError("group has no order/q attribute")

        # recompute A = g^{s̃}·X^{−c̃}
        A = g.Base.exp(self.s_tilde) * self.X.exp(-self.c_tilde)

        # verify final signature: c == H(X || D || A || m || b'final')
        c_check = g.bytes_to_exponent(
            hash(self.X.to_bytes(), self.D_bytes, A.to_bytes(), self.message_bytes, b'final')
        )
        if c_check != c:
            raise InvalidSignatureError("final signature hash mismatch")

        # extract d = (s – c) · c̃^(−1) mod order
        inv_c_tilde = pow(self.c_tilde, -1, order)
        d = (s - c) * inv_c_tilde % order

        # END YOUR CODE SNIPPET HERE
        return g.exponent_to_bytes(d)
