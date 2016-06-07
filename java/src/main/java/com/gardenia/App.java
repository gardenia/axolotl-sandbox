package com.gardenia;

import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.util.Scanner;

import org.whispersystems.libaxolotl.AxolotlAddress;
import org.whispersystems.libaxolotl.DecryptionCallback;
import org.whispersystems.libaxolotl.DuplicateMessageException;
import org.whispersystems.libaxolotl.IdentityKey;
import org.whispersystems.libaxolotl.IdentityKeyPair;
import org.whispersystems.libaxolotl.InvalidKeyException;
import org.whispersystems.libaxolotl.InvalidKeyIdException;
import org.whispersystems.libaxolotl.InvalidMessageException;
import org.whispersystems.libaxolotl.InvalidVersionException;
import org.whispersystems.libaxolotl.LegacyMessageException;
import org.whispersystems.libaxolotl.NoSessionException;
import org.whispersystems.libaxolotl.StaleKeyExchangeException;
import org.whispersystems.libaxolotl.SessionBuilder;
import org.whispersystems.libaxolotl.SessionCipher;
import org.whispersystems.libaxolotl.UntrustedIdentityException;
import org.whispersystems.libaxolotl.ecc.Curve;
import org.whispersystems.libaxolotl.protocol.CiphertextMessage;
import org.whispersystems.libaxolotl.protocol.KeyExchangeMessage;
import org.whispersystems.libaxolotl.protocol.PreKeyWhisperMessage;
import org.whispersystems.libaxolotl.protocol.WhisperMessage;
import org.whispersystems.libaxolotl.state.AxolotlStore;
import org.whispersystems.libaxolotl.state.SignedPreKeyRecord;
import org.whispersystems.libaxolotl.state.impl.InMemoryAxolotlStore;
import org.whispersystems.libaxolotl.state.impl.InMemoryIdentityKeyStore;
import org.whispersystems.libaxolotl.state.impl.InMemoryPreKeyStore;
import org.whispersystems.libaxolotl.state.impl.InMemorySessionStore;
import org.whispersystems.libaxolotl.state.impl.InMemorySignedPreKeyStore;
import org.whispersystems.libaxolotl.util.KeyHelper;
import org.whispersystems.libaxolotl.util.Medium;

/**
 * main
 */
public class App {
    private static final AxolotlAddress ALICE_ADDRESS = new AxolotlAddress("+14151111111", 1);
    private static final AxolotlAddress BOB_ADDRESS   = new AxolotlAddress("+14152222222", 1);

    public static void main(String[] args) {
        try {
            testBasicKeyExchange();
        }
        catch (StaleKeyExchangeException e) {
            e.printStackTrace();
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void testBasicKeyExchange()
        throws InvalidKeyException, LegacyMessageException, InvalidMessageException, DuplicateMessageException, UntrustedIdentityException, StaleKeyExchangeException, InvalidVersionException, NoSessionException, IOException {

        Identity alice = getAlice();
        Identity bob = getBob();

        InMemoryAxolotlStore aliceStore = new InMemoryAxolotlStore(alice.getKeypair(), alice.regid);
        InMemoryAxolotlStore bobStore = new InMemoryAxolotlStore(bob.getKeypair(), bob.regid);

        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

        KeyExchangeMessage aliceKeyExchangeMessage = aliceSessionBuilder.process();
        assert(aliceKeyExchangeMessage != null);

        byte[] aliceKeyExchangeMessageBytes = aliceKeyExchangeMessage.serialize();
        System.out.println("ALICE keyexchange initiate >>> " + bytesToHex(aliceKeyExchangeMessageBytes));

        Console c = System.console();
        if (c == null) {
            System.err.println("No console.");
            System.exit(1);
        }

        System.out.println("\n");
        String bobKeyExchangeHex = c.readLine("Enter BOB keyexchange response : ");
        System.out.println(bobKeyExchangeHex.getBytes());
        byte[] bobKeyExchangeMessageTmp = hexToBytes(bobKeyExchangeHex.toCharArray());

        KeyExchangeMessage bobKeyExchangeMessage = new KeyExchangeMessage(bobKeyExchangeMessageTmp);
        byte[] bobKeyExchangeMessageBytes = bobKeyExchangeMessage.serialize();
        KeyExchangeMessage response  = aliceSessionBuilder.process(new KeyExchangeMessage(bobKeyExchangeMessageBytes));

        assert(response == null);
        assert(aliceStore.containsSession(BOB_ADDRESS));
        assert(bobStore.containsSession(ALICE_ADDRESS));

        // runInteraction
        SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
        SessionCipher bobSessionCipher   = new SessionCipher(bobStore, ALICE_ADDRESS);

        String originalMessage = "Hello world";
        CiphertextMessage aliceMessage = aliceSessionCipher.encrypt(originalMessage.getBytes());
        System.out.println("MESSAGE[HEX] >>> " + bytesToHex(aliceMessage.serialize()));
    }

    private static String bytesToHex(byte[] bytes) {
        final char[] hexArray = "0123456789abcdef".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    private static byte[] hexToBytes(char[] hex) {
        byte[] raw = new byte[hex.length / 2];
        for (int src = 0, dst = 0; dst < raw.length; ++dst) {
            int hi = Character.digit(hex[src++], 16);
            int lo = Character.digit(hex[src++], 16);
            if ((hi < 0) || (lo < 0))
                throw new IllegalArgumentException();
            raw[dst] = (byte) (hi << 4 | lo);
        }
        return raw;
    } 

    // canned Alice and Bob identiy keys for consistency
    private static Identity getAlice() {
        final AxolotlAddress address = new AxolotlAddress("+14151111111", 1);

        final byte[] keypair = new byte[] {
             (byte)0x0a,(byte)0x21,(byte)0x05,(byte)0x88,(byte)0x25,(byte)0xd0,(byte)0xf0,(byte)0x50,
             (byte)0x92,(byte)0x5c,(byte)0xd3,(byte)0xb6,(byte)0x71,(byte)0xaf,(byte)0xfe,(byte)0xb1,
             (byte)0x1c,(byte)0xde,(byte)0x9f,(byte)0x29,(byte)0xdd,(byte)0x7d,(byte)0x64,(byte)0xd9,
             (byte)0xf4,(byte)0xe5,(byte)0xc9,(byte)0xdc,(byte)0x3f,(byte)0x04,(byte)0xe7,(byte)0xb8,
             (byte)0xc4,(byte)0xab,(byte)0x10,(byte)0x12,(byte)0x20,(byte)0x58,(byte)0xca,(byte)0xca,
             (byte)0x5e,(byte)0xef,(byte)0x86,(byte)0x5e,(byte)0xb9,(byte)0xb2,(byte)0xd4,(byte)0xf7,
             (byte)0xd3,(byte)0x86,(byte)0xee,(byte)0x3c,(byte)0x4f,(byte)0xfa,(byte)0x43,(byte)0x84,
             (byte)0x44,(byte)0x8e,(byte)0xa7,(byte)0xcc,(byte)0xb7,(byte)0x9a,(byte)0x40,(byte)0xdc,
             (byte)0x09,(byte)0x72,(byte)0x17,(byte)0x7a,(byte)0x46
        };

        final int regid = 1978;

        return new Identity("alice", address, keypair, regid);
    }

    private static Identity getBob() {
        final AxolotlAddress address = new AxolotlAddress("+14152222222", 1);

        final byte[] keypair = new byte[] {
            (byte)0x0a,(byte)0x21,(byte)0x05,(byte)0x5a,(byte)0x93,(byte)0x31,(byte)0x15,(byte)0x95,
            (byte)0x99,(byte)0x49,(byte)0x06,(byte)0x4f,(byte)0x48,(byte)0xa3,(byte)0xf8,(byte)0xaf,
            (byte)0xa6,(byte)0xce,(byte)0x74,(byte)0x09,(byte)0xb3,(byte)0x80,(byte)0xbe,(byte)0x24,
            (byte)0x24,(byte)0x8b,(byte)0x41,(byte)0xba,(byte)0xbc,(byte)0x30,(byte)0x26,(byte)0x88,
            (byte)0x93,(byte)0xc5,(byte)0x73,(byte)0x12,(byte)0x20,(byte)0xd0,(byte)0xb5,(byte)0xb4,
            (byte)0xe0,(byte)0xb3,(byte)0x65,(byte)0xc8,(byte)0xe9,(byte)0xd1,(byte)0x75,(byte)0xf6,
            (byte)0x7d,(byte)0x25,(byte)0x57,(byte)0x18,(byte)0x28,(byte)0x08,(byte)0xce,(byte)0xfc,
            (byte)0xcb,(byte)0x6e,(byte)0x95,(byte)0x56,(byte)0xb4,(byte)0x71,(byte)0x7e,(byte)0x7e,
            (byte)0xef,(byte)0x40,(byte)0x09,(byte)0x1b,(byte)0x45
        };

        final int regid = 7803;

        return new Identity("bob", address, keypair, regid);
    }

    private static class Identity {
        public final String name;
        public final AxolotlAddress address;
        public final int regid;
        private final byte[] keypair;

       Identity(String name, AxolotlAddress address, byte[] keypair, int regid) {
           this.name = name;
           this.address = address;
           this.keypair = keypair;
           this.regid = regid;
       }

       public IdentityKeyPair getKeypair() throws IOException, InvalidKeyException {
           return new IdentityKeyPair(keypair);
       }

       public int getRegistrationId() {
          return regid;
       }
    }
}
