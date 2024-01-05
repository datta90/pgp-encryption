import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.Optional;
import java.nio.file.Path;
import java.nio.file.Paths;

public class PgpEncryptionTest {

//    private static URL loadResource(String resourcePath) {
//        return Optional.ofNullable(PgpEncryptionTest.class.getResource(resourcePath))
//                .orElseThrow(() -> new IllegalArgumentException("Resource not found"));
//    }

    private static final String passkey = "datta#123";
    private static final URL privateKey;

    static {
        try {
            privateKey = new File("/home/datta/PGP/datta-private.asc").toURI().toURL();
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    private static final URL publicKey;

    static {
        try {
            publicKey = new File("/home/datta/PGP/datta-public.asc").toURI().toURL();
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    private static final URL testFile;

    static {
        try {
            testFile = new File("/home/datta/PGP/document.pdf").toURI().toURL();
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    private static final String encrypted_file = "/home/datta/PGP/encryptedFileOutput.gpg";

    public static void testFileEncryption(PgpEncryptionUtil pgpEncryptionUtil,PgpDecryptionUtil pgpDecryptionUtil) throws IOException, URISyntaxException, PGPException {
        // Generating a pgp encrypted temp file from the test file
        File encryptedFile = new File(encrypted_file);
        File originalFile = new File(testFile.toURI());
//        try (OutputStream fos = Files.newOutputStream(encryptedFile.toPath())) {
//            pgpEncryptionUtil.encrypt(fos, Files.newInputStream(originalFile.toPath()), originalFile.length(),
//                    publicKey.openStream());
//        }
        // Decrypting the generated pgp encrypted temp file and writing to another temp file
        File decryptedFile = new File("/home/datta/PGP/file.decrypted");
        pgpDecryptionUtil.decrypt(Files.newInputStream(encryptedFile.toPath()), Files.newOutputStream(decryptedFile.toPath()));
        // Comparing the original file contents with the decrypted file contents
//        assertEquals(IOUtils.toString(Files.newInputStream(originalFile.toPath()), Charset.defaultCharset()),
//                IOUtils.toString(Files.newInputStream(decryptedFile.toPath()), Charset.defaultCharset()));
    }

public static void main (String[] args) throws PGPException, IOException, URISyntaxException {
    PgpEncryptionUtil pgpEncryptionUtil = PgpEncryptionUtil.builder()
            .armor(true)
            .compressionAlgorithm(CompressionAlgorithmTags.BZIP2)
            .symmetricKeyAlgorithm(SymmetricKeyAlgorithmTags.AES_256)
            .withIntegrityCheck(true)
            .build();


    PgpDecryptionUtil pgpDecryptionUtil;
    try {
        pgpDecryptionUtil = new PgpDecryptionUtil(privateKey.openStream(), passkey);
    } catch (IOException | PGPException e) {
        throw new RuntimeException(e);
    }

    testFileEncryption(pgpEncryptionUtil, pgpDecryptionUtil);


}



}
