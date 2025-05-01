#!/usr/bin/env python3

import os


def main():

    print("Welcome to the Schnorr exchange protocol.")

    from schnorr import Schnorr_Exchange, SideProver, SideVerifier, InvalidPreSignatureError, InvalidSignatureError
    from schnorr.groups import Params3072, Params1024

    params = Params3072

    alice = Schnorr_Exchange(side=SideProver, params=params)
    bob = Schnorr_Exchange(side=SideVerifier, params=params)

    alice_setup_statement = alice.generate_statement()
    bob_statement = bob.set_statement(alice_setup_statement)

    pre_signature = alice.pre_sign_message(*bob_statement)
    signature = bob.sign_message(pre_signature)
    witness = alice.extract_witness(signature)

    if witness == bob.get_dlog_statement_witness():
        print('Alice successfully retrieved the witness in exchange of her signature')
    else:
        raise Exception('Alice did not obtain the witness!')

    try:
        # BEGIN YOUR CODE SNIPPET HERE
        
        # Corrupt Alice’s pre-signature challenge so Bob’s check fails:
        bad_c_tilde = bytearray(pre_signature[0])
        bad_c_tilde[0] ^= 0x01  # flip low bit
        pre_signature = (bytes(bad_c_tilde), pre_signature[1])
        
        # END YOUR CODE SNIPPET HERE
        
        bob.sign_message(pre_signature)
    except InvalidPreSignatureError:
        print('Bob correctly raises an exception when the presignature is invalid')
    else:
        raise Exception('Bob did not raise an exception for an invalid presignature!')

    try:
        # BEGIN YOUR CODE SNIPPET HERE
        
        # Corrupt Bob’s final signature so Alice’s extraction fails:
        bad_c = bytearray(signature[0])
        bad_c[-1] ^= 0x01  # flip low bit
        signature = (bytes(bad_c), signature[1])
        
        # END YOUR CODE SNIPPET HERE

        alice.extract_witness(signature)
    except InvalidSignatureError:
        print('Alice correctly raises an exception when the signature is invalid')
    else:
        raise Exception('Alice did not raise an exception for an incorrect signature!')


if __name__ == "__main__":
    main()
