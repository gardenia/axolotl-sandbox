
# coding=utf-8

import binascii
import sys
import traceback

from axolotl.sessionbuilder import SessionBuilder
from axolotl.sessioncipher import SessionCipher
from axolotl.ecc.curve import Curve
from axolotl.protocol.ciphertextmessage import CiphertextMessage
from axolotl.protocol.whispermessage import WhisperMessage
from axolotl.protocol.prekeywhispermessage import PreKeyWhisperMessage
from axolotl.state.prekeybundle import PreKeyBundle
from axolotl.tests.inmemoryaxolotlstore import InMemoryAxolotlStore
from axolotl.state.prekeyrecord import PreKeyRecord
from axolotl.state.signedprekeyrecord import SignedPreKeyRecord
from axolotl.tests.inmemoryidentitykeystore import InMemoryIdentityKeyStore
from axolotl.protocol.keyexchangemessage import KeyExchangeMessage
from axolotl.untrustedidentityexception import UntrustedIdentityException

BOB_RECIPIENT_ID = 2

def handle_keyexchange(store, who, body):
    messageBytes = binascii.unhexlify(body)
    print("UNWRAPPED >>> [%r]" % binascii.hexlify(messageBytes))

    try:
        sb = SessionBuilder(store, store, store, store, who, 1)
        print("SessionBuilder >>>", sb)

        ke = KeyExchangeMessage(serialized=bytearray(messageBytes))
        print("KeyExchangeMessage >>>", ke)

        response = sb.processKeyExchangeMessage(ke)
        print("RESPONSE >>>", response)

        if response:
            print("RESPONSE >>> %r" % repr(response))
            return binascii.hexlify(response.serialize())

    except Exception as e:
        print("EXCEPTION >>>", e)

        exc_type, exc_value, exc_traceback = sys.exc_info()
        print("*** print_tb:")
        traceback.print_tb(exc_traceback, limit=1, file=sys.stdout)

def handle_data_msg(store, who, body):
    messageBytes = binascii.unhexlify(body)
    print("UNWRAPPED >>> [%r]" % binascii.hexlify(messageBytes))

    try:
        sc = SessionCipher(store, store, store, store, who, 1)
        print("SessionCipher >>>", sc)

        wm = WhisperMessage(serialized=messageBytes)
        print("WhisperMessage >>>", wm)

        data = sc.decryptMsg(wm)
        print("DECRYPTED >>> ", data)

    except Exception as e:
        print("EXCEPTION >>>", e)

        exc_type, exc_value, exc_traceback = sys.exc_info()
        print("*** print_tb:")
        traceback.print_tb(exc_traceback, limit=1, file=sys.stdout)

def main():
    aliceStore = InMemoryAxolotlStore()
    aliceSessionBuilder = SessionBuilder(aliceStore, aliceStore, aliceStore, aliceStore, BOB_RECIPIENT_ID, 1)

    raw_ke = input("Enter key exchange: ")
    response = handle_keyexchange(aliceStore, BOB_RECIPIENT_ID, raw_ke.rstrip())
    print
    print
    print("RESPONSE >>>", response)

    raw_message = input("Enter raw message: ")
    print
    print
    handle_data_msg(aliceStore, BOB_RECIPIENT_ID, raw_message.rstrip())

if __name__ == "__main__":
    main()
