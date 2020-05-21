package com.im.single;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.state.impl.InMemorySignalProtocolStore;
import org.whispersystems.libsignal.util.KeyHelper;


    public class ChatInMemorySignalProtocolStore extends InMemorySignalProtocolStore {
        public ChatInMemorySignalProtocolStore() {
            super(generateIdentityKeyPair(), generateRegistrationId());
        }

        public ChatInMemorySignalProtocolStore(IdentityKeyPair identityKeyPair, int registrationId) {
            super(identityKeyPair, registrationId);
        }

        public static IdentityKeyPair generateIdentityKeyPair() {
            ECKeyPair identityKeyPairKeys = Curve.generateKeyPair();

            return new IdentityKeyPair(new IdentityKey(identityKeyPairKeys.getPublicKey()),
                    identityKeyPairKeys.getPrivateKey());
        }

        public static int generateRegistrationId() {
            return KeyHelper.generateRegistrationId(false);
        }
    }

