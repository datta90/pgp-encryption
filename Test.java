import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.*;

import java.io.*;

import java.security.SecureRandom;
import java.util.Iterator;
import java.security.Security;



public class Test {

    public static PGPSecretKey readSecretKeyFromCol(InputStream in, long keyId) throws IOException, PGPException
    {
        in = PGPUtil.getDecoderStream(in);
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(in, new BcKeyFingerprintCalculator());
        PGPSecretKey key = pgpSec.getSecretKey(keyId);
        if (key == null) {
            throw new IllegalArgumentException("Can't find encryption key in key ring.");
        }
        return key;
    }
    public static PGPPublicKey readPublicKeyFromCol(InputStream in) throws IOException, PGPException
    {
        in = PGPUtil.getDecoderStream(in);
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in, new BcKeyFingerprintCalculator());
        PGPPublicKey key = null;
        Iterator<PGPPublicKeyRing> rIt = pgpPub.getKeyRings();
        while (key == null && rIt.hasNext()) {
            PGPPublicKeyRing kRing = rIt.next();
            Iterator<PGPPublicKey> kIt = kRing.getPublicKeys();
            while (key == null && kIt.hasNext()) {
                PGPPublicKey k = kIt.next();
                if (k.isEncryptionKey()) {
                    key = k;
                }
            }
        }
        if (key == null) {
            throw new IllegalArgumentException("Can't find encryption key in key ring.");
        }
        return key;
    }
    public static void decryptFile(InputStream in, InputStream secKeyIn, InputStream pubKeyIn, char[] pass)
            throws IOException, PGPException {
        Security.addProvider(new BouncyCastleProvider());
        PGPPublicKey pubKey = readPublicKeyFromCol(pubKeyIn);
        //PGPSecretKey secKey = readSecretKeyFromCol(secKeyIn, pubKey.getKeyID());
        in = PGPUtil.getDecoderStream(in);
        JcaPGPObjectFactory pgpFact;
        PGPObjectFactory pgpF = new PGPObjectFactory(in, new BcKeyFingerprintCalculator());
        Object o = pgpF.nextObject();
        PGPEncryptedDataList encList;
        if (o instanceof PGPEncryptedDataList) {
            encList = (PGPEncryptedDataList) o;
        } else {
            encList = (PGPEncryptedDataList) pgpF.nextObject();
        }
        Iterator<PGPEncryptedData> itt = encList.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData encP = null;
        while (sKey == null && itt.hasNext()) {
            encP = (PGPPublicKeyEncryptedData) itt.next();
            PGPSecretKey secKey = readSecretKeyFromCol(secKeyIn, encP.getKeyID());
            sKey = secKey.extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(pass));
        }
        if (sKey == null) {
            throw new IllegalArgumentException("Secret key for message not found.");
        }
        InputStream clear = encP.getDataStream(new BcPublicKeyDataDecryptorFactory(sKey));
        pgpFact = new JcaPGPObjectFactory(clear);
        PGPCompressedData c1 = (PGPCompressedData) pgpFact.nextObject();
        pgpFact = new JcaPGPObjectFactory(c1.getDataStream());
        PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        InputStream inLd = ld.getDataStream();
        int ch;
        while ((ch = inLd.read()) >= 0) {
            bOut.write(ch);
        }
        //System.out.println(bOut.toString());

        bOut.writeTo(new FileOutputStream(ld.getFileName()));
        //return bOut;
    }
    public static void encryptFile(OutputStream out, String fileName, PGPPublicKey encKey)
            throws IOException, PGPException {
        Security.addProvider(new BouncyCastleProvider());
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
        PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY, new File(fileName));
        comData.close();
        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setSecureRandom(new SecureRandom()));
        cPk.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(encKey));
        byte[] bytes = bOut.toByteArray();
        OutputStream cOut = cPk.open(out, bytes.length);
        cOut.write(bytes);
        cOut.close();
        out.close();
    }

    public static void main (String[] args)
            throws IOException {

        try {
            //decryptFile(new FileInputStream("/home/datta/PGP/touch.enc"), new FileInputStream("/home/datta/PGP/datta-private.asc"), new FileInputStream("/home/datta/PGP/datta-public.asc"), "datta#123".toCharArray());
            PGPPublicKey pubKey = readPublicKeyFromCol(new FileInputStream("/home/datta/PGP/datta-public.asc"));
            encryptFile(new FileOutputStream("/home/datta/PGP/encryptedFileOutput.gpg"), "/home/datta/PGP/text.txt", pubKey);
        } catch (PGPException e) {
            System.out.print("exception: " + e.getMessage());
        }



    }


    }
