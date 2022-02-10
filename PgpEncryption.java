//
// This is a variation of the example found in the Bouncy Castle Java examples on github.
// I'm using a public key provided by 3rd party to encrypt a file before sending to them. They
// have the private key so it's a one-way system, I have no need for a decrypt method. This is
// being used in a Spring Boot app, hence the annotations.
//

import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.*;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;

@Service
public class PgpEncryption {

    private static final Logger LOG = LoggerFactory.getLogger(PgpEncryption.class);

    @Value("${pgp.passphrase}")
    private String _passphrase;

    @Value("${pgp.keyFile}")
    private String _keyFile;

    public PgpEncryption() {
        LOG.info("Configuring PGP using Bouncy Castle");
        Security.addProvider(new BouncyCastleProvider());
    }

    public void encrypt(final String inputFile, final String outputFile) throws IOException, PGPException, NoSuchProviderException {
        try (final InputStream keyIn = new FileInputStream(_keyFile);
             final OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFile))) {
            encryptFile(out, inputFile, readPublicKey(keyIn));
        }
    }

    private byte[] compressFile(String fileName, int algorithm) throws IOException {
        final ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        final PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(algorithm);
        PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY, new File(fileName));
        comData.close();
        return bOut.toByteArray();
    }

    private PGPPublicKey readPublicKey(InputStream input) throws IOException, PGPException {
        final PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());

        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //
        final Iterator keyRingIter = pgpPub.getKeyRings();

        while (keyRingIter.hasNext()) {
            final PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIter.next();
            final Iterator keyIter = keyRing.getPublicKeys();

            while (keyIter.hasNext()) {
                final PGPPublicKey key = (PGPPublicKey) keyIter.next();

                if (key.isEncryptionKey()) {
                    LOG.info("found {} bit public key", key.getBitStrength());
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

    private void encryptFile(final OutputStream out, final String fileName, final PGPPublicKey encKey) throws IOException, NoSuchProviderException {
        try {
            final byte[] bytes = compressFile(fileName, CompressionAlgorithmTags.ZIP);

            final PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
                            .setWithIntegrityPacket(true)
                            .setSecureRandom(new SecureRandom())
                            .setProvider("BC"));

            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));

            final OutputStream cOut = encGen.open(out, bytes.length); // the returned output stream is not auto closeable

            cOut.write(bytes);
            cOut.close();
        } catch (final PGPException e) {
            LOG.error("There was a problem encrypting file", e);
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        }
    }

}
