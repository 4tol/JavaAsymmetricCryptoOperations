package com.tolpp.sandbox;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.*;
import org.junit.rules.TestName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

//
// 1- Generate private key:
//      openssl genrsa -out rsa_2048.pem 2048
// 2- Convert private key to PKCS8 Format:
//      openssl pkcs8 -topk8 -inform PEM -in rsa_2048.pem -out rsa_2048_pkcs8.pem -nocrypt
// Extract public key:
//      openssl rsa -in rsa_2048.pem -pubout > rsa_2048.pub
//
public class RsaOperationTest {
    private static final Logger logger = LoggerFactory.getLogger(RsaOperationTest.class);
    private static final org.apache.commons.codec.binary.Base64 base64 = new org.apache.commons.codec.binary.Base64();

    private static final String RSA_2048_PRIVATE_PKCS8 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCxIZImi+UM7IKB\n" +
            "f3LvT9ccQnIhTFx58fec81a6DA411VzgVV/ZiFyrONSlsVV//gTfi8rAAwMAuy0w\n" +
            "g57xKcEO/4BhBV3j2RNdR0SAmGzqlaueex7A8CB81Vvls1jVvXKaHFgemV+4dwbm\n" +
            "GZpfzD8FizUXdB14e24RvlSE+tH3+iGfTYSwn4/MnMcXJA1uao7C90eO7OVPoKHQ\n" +
            "em9KqMQgCfXEQaCYtFK+5qmSW7S7FHRDk2XhEk/xsQ0KEKHy4l9z4LWVPQkSssrR\n" +
            "rH7ox12Rfo1weQfxob0YYR8QdfdEnAuIgNK1uqVB2XAhIFV64jyXFO1sI60n4q1f\n" +
            "lJviKXHFAgMBAAECggEAItaxgjdds68I9CN3Ha6cZoiDHh2AytNWml4aHrmkSd5P\n" +
            "SChCk+yIHX0uBfDdGjGCD93U4PM2sfwepT4eEtzdhe+m9m4xy1C0yFHuHUTdlz4c\n" +
            "5SzeHaCdIzBrxMADpvZ+BeWxR0NvWj6+8p7yiAkKFDMPHC/QZBQS0BaZVRZoGdea\n" +
            "1a7S9uU3xGIkCFFL9othMWg32Tm8cRgUfDKI1By7cderbIERfStz0gGR1xIqOINh\n" +
            "/f/BiOQfUAUm+29V07E2UdnXP3gcQuDBPDPafQ5CbRlGYWHsjpsbRJRMdMBSkzrR\n" +
            "X8h0cCqTizrEgGxqG/XuYOkTnnzQP0OTEuJ5X7COwQKBgQDdLNEL0RlJjvq3PyaK\n" +
            "TIo8KzJy+Dq72RLOwX/LMIBr8IDWspxT2IuYwbzXHApdwgExVaFWnMiGkhOhzI03\n" +
            "w8UpyGWK5CzaOcSrhecHhYF9bkRLV3yeUKykfothlzOyAD3WJoxcJK5m2SVPx1e3\n" +
            "tUmM1ktuJS/8F7ygUZVtzQI8XQKBgQDNBWt/oZim46C0ABTxH0SLD2EvmZBn7WNU\n" +
            "5mdqajQcUK4n2ABM00konzI+92jyqih2VyGI/3WD3ALOVPE3rbkc+2+L5uXEQc/4\n" +
            "08sNohik2OqCZHMFFchfgjWvT+8RrcJVG4iTyehhuX1HA9l8rVOGqka537WNyh/j\n" +
            "ODqY2UF0iQKBgEQ9G5JFxUOItZnsBfwNeWju+vW12Ik0hDT+RmtuX3DuFxImsUy9\n" +
            "NvS+cYD8ycX7oVqTTN/oJ4Y9c4ksDzXxVNd7WLjthVkfEarJ+Wm8qyMD7lZAe9Zs\n" +
            "lZd6444MlIqKwIleA1g6iQR6YqSmoE2xxSuKwmMNXiytNilQgoYKBnKRAoGBAMhA\n" +
            "7AAtShpwqg5HKi1emiet7QJ+X1NzxpsttYN2mtGxaHpYe+qOUZ4Q6RYhuOuVkpIM\n" +
            "hx/2TcVux3rb8wSsdew+F3UyIekxUz87N9FoK+QQT/buwH4OCbpoR6GmVOAStYdF\n" +
            "roCULZwOfrQ3qV4jOjuF5DE3tnD5JW5eBLY5NrrpAoGAOLD2Q0KW19kRf1qKKPD/\n" +
            "UHvQD3yvLgyhAms4cCuA5qhB2TKIUDMF0tUr6wlniOz5Byvqu/dwrcVWiF8oosoH\n" +
            "lbg1xoHE00Jb4GiusujFrEiUQt5p9dbItrEKt/SNhGbvwufAIhBFc0yUAVNkPJyI\n" +
            "lSrSk5I9DT1fKL1WYMAwPMc=";

    private static final String RSA_2048_PUBLIC = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsSGSJovlDOyCgX9y70/X\n" +
            "HEJyIUxcefH3nPNWugwONdVc4FVf2YhcqzjUpbFVf/4E34vKwAMDALstMIOe8SnB\n" +
            "Dv+AYQVd49kTXUdEgJhs6pWrnnsewPAgfNVb5bNY1b1ymhxYHplfuHcG5hmaX8w/\n" +
            "BYs1F3QdeHtuEb5UhPrR9/ohn02EsJ+PzJzHFyQNbmqOwvdHjuzlT6Ch0HpvSqjE\n" +
            "IAn1xEGgmLRSvuapklu0uxR0Q5Nl4RJP8bENChCh8uJfc+C1lT0JErLK0ax+6Mdd\n" +
            "kX6NcHkH8aG9GGEfEHX3RJwLiIDStbqlQdlwISBVeuI8lxTtbCOtJ+KtX5Sb4ilx\n" +
            "xQIDAQAB";

    private final static String sampleDataStr = "Tolga Okur, Lorem ipsum dolor sit amet, consectetur adipiscing elit.";

    private static final byte[] sampleDataBytes = sampleDataStr.getBytes(StandardCharsets.UTF_8);

    private static RSAPrivateKey rsaPrivateKey;
    private static RSAPublicKey rsaPublicKey;

    //      MD2:     (0x)30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 02 05 00 04
    //                   10 || H.
    //      MD5:     (0x)30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 05 05 00 04
    //                   10 || H.
    //      SHA-1:   (0x)30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 || H.
    //      SHA-256: (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00
    //                   04 20 || H.
    //      SHA-384: (0x)30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00
    //                   04 30 || H.
    //      SHA-512: (0x)30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00
    //                      04 40 || H.
    private static byte[] RSA_SHA_256_PREFIX;
    @Rule
    public TestName testName = new TestName();

    @BeforeClass
    public static void setupClass() throws Exception {
        byte[] keyBytes = base64.decode(RSA_2048_PRIVATE_PKCS8);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        rsaPrivateKey = (RSAPrivateKey) kf.generatePrivate(spec);

        byte[] publicKeyBytes = base64.decode(RSA_2048_PUBLIC);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        rsaPublicKey = (RSAPublicKey) kf.generatePublic(publicKeySpec);

        RSA_SHA_256_PREFIX = Hex.decodeHex("3031300d060960864801650304020105000420");
    }

    @Before
    public void setup() {
        logger.info("== " + testName.getMethodName() + " ==");
    }

    /**
     * Just a regular encryption and decryption
     */
    @Test
    public void encryptWithPublicKeyDecryptWithPrivateKey() throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
        byte[] encryptedData = encryptCipher.doFinal(sampleDataBytes);

        logger.info("Encrypt with public key: ");
        logger.info(Hex.encodeHexString(encryptedData));

        Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        decryptCipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
        byte[] decryptedData = decryptCipher.doFinal(encryptedData);

        logger.info("Decrypt with private key: ");
        logger.info(new String(decryptedData));

        Assert.assertArrayEquals(sampleDataBytes, decryptedData);
    }

    /**
     * Sign-Verify equivalent by encrypting/decrypting
     */
    @Test
    public void encryptWithPrivateKeyDecryptWithPublicKey() throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, rsaPrivateKey);
        byte[] encryptedData = encryptCipher.doFinal(sampleDataBytes);

        logger.info("Encrypt with private key: ");
        logger.info(Hex.encodeHexString(encryptedData));

        Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        decryptCipher.init(Cipher.DECRYPT_MODE, rsaPublicKey);
        byte[] decryptedData = decryptCipher.doFinal(encryptedData);

        logger.info("Decrypt with public key: ");
        logger.info(new String(decryptedData));

        Assert.assertArrayEquals(sampleDataBytes, decryptedData);
    }

    /**
     * First, decrypt plain data with public key, then encrypt with private key.
     */
    @Test
    public void decryptWithPublicKeyEncryptWithPrivateKey() throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/NoPadding");
        encryptCipher.init(Cipher.DECRYPT_MODE, rsaPublicKey);
        byte[] encryptedData = encryptCipher.doFinal(sampleDataBytes);

        logger.info("Decrypt sample data with public key: ");
        logger.info(Hex.encodeHexString(encryptedData));

        Cipher decryptCipher = Cipher.getInstance("RSA/ECB/NoPadding");
        decryptCipher.init(Cipher.ENCRYPT_MODE, rsaPrivateKey);
        byte[] decryptedData = decryptCipher.doFinal(encryptedData);

        logger.info("Encrypt decrypted data with private key");
        logger.info(new String(decryptedData));
        Assert.assertArrayEquals(sampleDataBytes, Arrays.copyOfRange(decryptedData, decryptedData.length - sampleDataBytes.length, decryptedData.length));
    }

    /**
     * Test Cipher.ENCRYPT_MODE and Cipher.DECRYPT_MODE doesn't change anything for rsaPublicKey
     */
    @Test
    public void encryptAndDecryptWithPublicKey() throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/NoPadding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
        byte[] encryptedData = encryptCipher.doFinal(sampleDataBytes);

        logger.info("Encrypt sample data with rsa public key: ");
        logger.info(Hex.encodeHexString(encryptedData));

        Cipher decryptCipher = Cipher.getInstance("RSA/ECB/NoPadding");
        decryptCipher.init(Cipher.DECRYPT_MODE, rsaPublicKey);
        byte[] decryptedData = decryptCipher.doFinal(sampleDataBytes);

        logger.info("Decrypt sample data with rsa public key: ");
        logger.info(Hex.encodeHexString(decryptedData));

        Assert.assertArrayEquals(encryptedData, decryptedData);
    }

    /**
     * Test Cipher.ENCRYPT_MODE and Cipher.DECRYPT_MODE doesn't change anything for rsaPrivateKey
     */
    @Test
    public void encryptAndDecryptWithPrivateKey() throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/NoPadding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, rsaPrivateKey);
        byte[] encryptedData = encryptCipher.doFinal(sampleDataBytes);

        logger.info("Encrypt sample data with rsa private key: ");
        logger.info(Hex.encodeHexString(encryptedData));

        Cipher decryptCipher = Cipher.getInstance("RSA/ECB/NoPadding");
        decryptCipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
        byte[] decryptedData = decryptCipher.doFinal(sampleDataBytes);

        logger.info("Decrypt sample data with rsa private key: ");
        logger.info(Hex.encodeHexString(decryptedData));

        Assert.assertArrayEquals(encryptedData, decryptedData);
    }

    /**
     * Sign data manually by getting digest first, and then encrypting data itself using rsa private key.
     * <p>
     * Then verify signature using {@link Signature} api.
     */
    @Test
    public void decryptSha256HashOfDataAndCheckSignatureUsingSHA256WithRSAAlgorithm() throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] sampleDataSha256 = sha256.digest(sampleDataBytes);
        byte[] hashWithDigestInfo = ArrayUtils.addAll(RSA_SHA_256_PREFIX, sampleDataSha256);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, rsaPrivateKey);
        byte[] encryptedData = cipher.doFinal(hashWithDigestInfo);

        logger.info("Encrypt sha256 hash of sample data with rsa private key: ");
        logger.info(Hex.encodeHexString(encryptedData));

        Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        decryptCipher.init(Cipher.DECRYPT_MODE, rsaPublicKey);
        byte[] decryptedData = decryptCipher.doFinal(encryptedData);

        Assert.assertArrayEquals(decryptedData, hashWithDigestInfo);

        Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initVerify(rsaPublicKey);
        signature.update(sampleDataBytes);
        boolean verified = signature.verify(encryptedData);

        Assert.assertTrue(verified);
    }

    /**
     * Sign data using Java's {@link Signature} api.
     * <p>
     * Check signature manually by decrypting data with rsa public key and comparing data hash with decrypted result.
     */
    @Test
    public void signWithPrivateKeyVerifyWithPublicKeyCipher() throws Exception {
        Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initSign(rsaPrivateKey);
        signature.update(sampleDataBytes);
        byte[] signBytes = signature.sign();

        logger.info("Signature:");
        logger.info(Hex.encodeHexString(signBytes));

        Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        decryptCipher.init(Cipher.DECRYPT_MODE, rsaPublicKey);
        byte[] decryptedData = decryptCipher.doFinal(signBytes);

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] sampleDataSha256 = sha256.digest(sampleDataBytes);
        byte[] hashWithDigestInfo = ArrayUtils.addAll(RSA_SHA_256_PREFIX, sampleDataSha256);

        Assert.assertArrayEquals(hashWithDigestInfo, decryptedData);
    }
}
