package com.RNRSA;


import android.annotation.TargetApi;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.KeyPairGeneratorSpec;

import android.util.Base64;
import android.content.Context;


import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.Calendar;
import java.math.BigInteger;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.security.auth.x500.X500Principal;

import java.io.IOException;



import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;


import static android.security.keystore.KeyProperties.*;

import static java.nio.charset.StandardCharsets.UTF_8;
import java.nio.charset.Charset;


public class RSA {
    public static Charset CharsetUTF_8;

    public static final String ALGORITHM = KeyProperties.KEY_ALGORITHM_RSA;

    private static final String PUBLIC_HEADER = "RSA PUBLIC KEY";
    private static final String PRIVATE_HEADER = "RSA PRIVATE KEY";
    private static final String CSR_HEADER = "CERTIFICATE REQUEST";

    private String keyTag;

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private PKCS10CertificationRequest csr;

    public RSA() {
        this.setupCharset();
    }

    public RSA(String keyTag) throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException, IOException, CertificateException {
        this.setupCharset();
        this.keyTag = keyTag;
        this.loadFromKeystore();
    }

    private void setupCharset() {
        if (android.os.Build.VERSION.SDK_INT >= 19) {
            CharsetUTF_8 = UTF_8;
        } else {
            CharsetUTF_8 = Charset.forName("UTF-8");
        }
    }

    public String getPublicKey() throws IOException {
        if (this.publicKey == null) {
            // This might be an Ed25519 key, which is handled separately
            throw new IOException("Public key is null - this might be an Ed25519 key which should use getPublicKeyEd()");
        }
        
        if (this.publicKey.getAlgorithm().equals("RSA")) {
            byte[] pkcs1PublicKey = publicKeyToPkcs1(this.publicKey);
            return dataToPem(PUBLIC_HEADER, pkcs1PublicKey);
        } else if (this.publicKey.getAlgorithm().equals("EC")) {
            // For EC keys, return the standard X.509 format encoded as base64
            return Base64.encodeToString(this.publicKey.getEncoded(), Base64.NO_WRAP);
        } else {
            // Fallback for other key types
            return Base64.encodeToString(this.publicKey.getEncoded(), Base64.NO_WRAP);
        }
    }

    public String getPublicKeyDER() throws IOException {
        if (this.publicKey == null) {
            throw new IOException("Public key is null");
        }
        
        // Return X.509 format (standard DER encoding with "PUBLIC KEY" header)
        return dataToPem("PUBLIC KEY", this.publicKey.getEncoded());
    }

    public String getPrivateKey() throws IOException {
        byte[] pkcs1PrivateKey = privateKeyToPkcs1(this.privateKey);
        return dataToPem(PRIVATE_HEADER, pkcs1PrivateKey);
    }

    public void setPublicKey(String publicKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        this.publicKey = pkcs1ToPublicKey(publicKey);
    }

    public void setPrivateKey(String privateKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] pkcs1PrivateKey = pemToData(privateKey);
        this.privateKey = pkcs1ToPrivateKey(pkcs1PrivateKey);
    }


    // This function will be called by encrypt and encrypt64
    private byte[] encrypt(byte[] data) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
        String encodedMessage = null;
        final Cipher cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
        byte[] cipherBytes = cipher.doFinal(data);
        return cipherBytes;
    }

    // Base64 input
    public String encrypt64(String b64Message) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
        byte[] data = Base64.decode(b64Message, Base64.NO_WRAP);
        byte[] cipherBytes = encrypt(data);
        return Base64.encodeToString(cipherBytes, Base64.NO_WRAP);
    }

    // UTF-8 input
    public String encrypt(String message) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
        byte[] data = message.getBytes(CharsetUTF_8);
        byte[] cipherBytes = encrypt(data);
        return Base64.encodeToString(cipherBytes, Base64.NO_WRAP);
    }

    private byte[] decrypt(byte[] cipherBytes) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
        String message = null;
        final Cipher cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
        byte[] data = cipher.doFinal(cipherBytes);
        return data;
    }

    // UTF-8 input
    public String decrypt(String message) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
        byte[] cipherBytes = Base64.decode(message, Base64.NO_WRAP);
        byte[] data = decrypt(cipherBytes);
        return new String(data, CharsetUTF_8);
    }

    // Base64 input
    public String decrypt64(String b64message) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
        byte[] cipherBytes = Base64.decode(b64message, Base64.NO_WRAP);
        byte[] data = decrypt(cipherBytes);
        return Base64.encodeToString(data, Base64.NO_WRAP);
    }

    private String sign(byte[] messageBytes, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException {

        Signature privateSignature = Signature.getInstance(algorithm);
        privateSignature.initSign(this.privateKey);
        privateSignature.update(messageBytes);
        byte[] signature = privateSignature.sign();
        return Base64.encodeToString(signature, Base64.NO_WRAP);
    }

    // b64 message
    public String sign64(String b64message, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException {
        byte[] messageBytes = Base64.decode(b64message, Base64.NO_WRAP);
        return sign(messageBytes, algorithm);
    }


    //utf-8 message
    public String sign(String message, String signature) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException {
        byte[] messageBytes = message.getBytes(CharsetUTF_8);
        return sign(messageBytes, signature);
    }

    private boolean verify(byte[] signatureBytes, byte[] messageBytes, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException {
        Signature publicSignature = Signature.getInstance(algorithm);
        publicSignature.initVerify(this.publicKey);
        publicSignature.update(messageBytes);
        return publicSignature.verify(signatureBytes);
    }

    // b64 message
    public boolean verify64(String signature, String message, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException {
        Signature publicSignature = Signature.getInstance(algorithm);
        publicSignature.initVerify(this.publicKey);
        byte[] messageBytes = Base64.decode(message, Base64.NO_WRAP);
        byte[] signatureBytes = Base64.decode(signature, Base64.NO_WRAP);
        return verify(signatureBytes, messageBytes, algorithm);
    }

    // utf-8 message
    public boolean verify(String signature, String message, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException {
        Signature publicSignature = Signature.getInstance(algorithm);
        publicSignature.initVerify(this.publicKey);
        byte[] messageBytes = message.getBytes(CharsetUTF_8);
        byte[] signatureBytes = Base64.decode(signature, Base64.NO_WRAP);
        return verify(signatureBytes, messageBytes, algorithm);
    }

    private String dataToPem(String header, byte[] keyData) throws IOException {
        PemObject pemObject = new PemObject(header, keyData);
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        return stringWriter.toString();
    }

    private byte[] pemToData(String pemKey) throws IOException {
        Reader keyReader = new StringReader(pemKey);
        PemReader pemReader = new PemReader(keyReader);
        PemObject pemObject = pemReader.readPemObject();
        return pemObject.getContent();
    }

    private PublicKey pkcs1ToPublicKey(String publicKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Reader keyReader = null;
        try {
            keyReader = new StringReader(publicKey);
            PEMParser pemParser = new PEMParser(keyReader);
            SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) pemParser.readObject();
            X509EncodedKeySpec spec = new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded());
            return KeyFactory.getInstance("RSA").generatePublic(spec);
               } finally {
            if (keyReader != null) {
                keyReader.close();
            }
        }
    }

    private PrivateKey pkcs1ToPrivateKey(byte[] pkcs1PrivateKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        ASN1InputStream in = new ASN1InputStream(pkcs1PrivateKey);
        ASN1Primitive obj = in.readObject();
        RSAPrivateKey keyStruct = RSAPrivateKey.getInstance(obj);
        RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(keyStruct.getModulus(), keyStruct.getPrivateExponent());
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePrivate(keySpec);
    }

    private byte[] publicKeyToPkcs1(PublicKey publicKey) throws IOException {
        SubjectPublicKeyInfo spkInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        ASN1Primitive primitive = spkInfo.parsePublicKey();
        return primitive.getEncoded();
    }

    private byte[] privateKeyToPkcs1(PrivateKey privateKey) throws IOException {
        PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
        ASN1Encodable encodeable = pkInfo.parsePrivateKey();
        ASN1Primitive primitive = encodeable.toASN1Primitive();
        return primitive.getEncoded();
    }

    public void loadFromKeystore() throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException, IOException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(this.keyTag, null);
        
        if (privateKeyEntry != null) {
            this.privateKey = privateKeyEntry.getPrivateKey();
            this.publicKey = privateKeyEntry.getCertificate().getPublicKey();
        }
    }

    public void deletePrivateKey() throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException, IOException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        keyStore.deleteEntry(this.keyTag);
        this.privateKey = null;
        this.publicKey = null;
    }

    public void generate() throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
       this.generate(2048);
    }

    public void generate(int keySize) throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM);
        kpg.initialize(keySize);

        KeyPair keyPair = kpg.genKeyPair();
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();
    }

    public void generate(String keyTag, Context context) throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        this.generate(keyTag, 2048, false, null, context);
    }
    
    @TargetApi(18)
    public void generate(String keyTag, int keySize, Context context) throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        this.generate(keyTag, keySize, false, null, context);
    }
    
    @TargetApi(18)
    public void generate(String keyTag, int keySize, boolean synchronizable, String label, Context context) throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM, "AndroidKeyStore");
        if (android.os.Build.VERSION.SDK_INT >= 23) {
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                keyTag,
                PURPOSE_ENCRYPT | PURPOSE_DECRYPT | PURPOSE_SIGN | PURPOSE_VERIFY
            )
            .setKeySize(keySize)
            .setDigests(DIGEST_SHA256, DIGEST_SHA512, DIGEST_SHA1)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1);
            
            // Note: Android KeyStore doesn't support synchronizable like iOS
            // The label parameter is also not directly supported in Android KeyStore
            // These parameters are accepted for API compatibility but not used
            
            kpg.initialize(builder.build());
        } else {
            Calendar endDate = Calendar.getInstance();
            endDate.add(Calendar.YEAR, 1);
            KeyPairGeneratorSpec.Builder keyPairGeneratorSpec = new KeyPairGeneratorSpec.Builder(context)
                .setAlias(keyTag)
                .setSubject(new X500Principal(
                    String.format("CN=%s, OU=%s", keyTag, context.getPackageName())
                ))
                .setSerialNumber(BigInteger.ONE)
                .setStartDate(Calendar.getInstance().getTime())
                .setEndDate(endDate.getTime());
            if (android.os.Build.VERSION.SDK_INT >= 19) {
                keyPairGeneratorSpec.setKeySize(keySize).setKeyType(ALGORITHM);
            }
            kpg.initialize(keyPairGeneratorSpec.build());
        }

        KeyPair keyPair = kpg.genKeyPair();
        this.publicKey = keyPair.getPublic();

    }

    @TargetApi(18)
    public void generateCSR(String commonName, String withAlgorithm, Context context) throws IOException, OperatorCreationException {
        this.csr = CsrHelper.generateCSR(this.publicKey, commonName, keyTag, withAlgorithm);
    }

    @TargetApi(18)
    public void generateCSRWithEC(String cn,String keyTag, int keySize, Context context) throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException, UnrecoverableEntryException, KeyStoreException, CertificateException {
        this.deletePrivateKey();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        if (android.os.Build.VERSION.SDK_INT >= 23) {

            kpg.initialize(new KeyGenParameterSpec.Builder(
                    keyTag,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256,
                            KeyProperties.DIGEST_SHA512,
                            DIGEST_SHA384,
                            KeyProperties.DIGEST_NONE)
                    .setKeySize(keySize)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
        } else {
            Calendar endDate = Calendar.getInstance();
            endDate.add(Calendar.YEAR, 1);
            KeyPairGeneratorSpec.Builder keyPairGeneratorSpec = new KeyPairGeneratorSpec.Builder(context)
                .setAlias(keyTag)
                .setSubject(new X500Principal(
                    String.format("CN=%s", keyTag, context.getPackageName())
                ))
                .setSerialNumber(BigInteger.ONE)
                .setStartDate(Calendar.getInstance().getTime())
                .setEndDate(endDate.getTime());
            if (android.os.Build.VERSION.SDK_INT >= 19) {
                keyPairGeneratorSpec.setKeySize(keySize).setKeyType(KeyProperties.KEY_ALGORITHM_EC);
            }
            kpg.initialize(keyPairGeneratorSpec.build());
        }


        KeyPair keyPair = kpg.genKeyPair();
        this.publicKey = keyPair.getPublic();

        try {
            this.csr = CsrHelper.generateCSRWithEC(this.publicKey, cn, keyTag);
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        }
    }

    @TargetApi(18)
    public void generateEC(String keyTag, boolean synchronizable, String label, Context context) throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        if (android.os.Build.VERSION.SDK_INT >= 23) {
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                keyTag,
                PURPOSE_SIGN | PURPOSE_VERIFY
            )
            .setKeySize(256)
            .setDigests(DIGEST_SHA256, DIGEST_SHA512, DIGEST_SHA1);
            
            // Note: Android KeyStore doesn't support synchronizable like iOS
            // The label parameter is also not directly supported in Android KeyStore
            // These parameters are accepted for API compatibility but not used
            
            kpg.initialize(builder.build());
        } else {
            Calendar endDate = Calendar.getInstance();
            endDate.add(Calendar.YEAR, 1);
            KeyPairGeneratorSpec.Builder keyPairGeneratorSpec = new KeyPairGeneratorSpec.Builder(context)
                .setAlias(keyTag)
                .setSubject(new X500Principal(
                    String.format("CN=%s, OU=%s", keyTag, context.getPackageName())
                ))
                .setSerialNumber(BigInteger.ONE)
                .setStartDate(Calendar.getInstance().getTime())
                .setEndDate(endDate.getTime());
            if (android.os.Build.VERSION.SDK_INT >= 19) {
                keyPairGeneratorSpec.setKeySize(256).setKeyType(KeyProperties.KEY_ALGORITHM_EC);
            }
            kpg.initialize(keyPairGeneratorSpec.build());
        }

        KeyPair keyPair = kpg.genKeyPair();
        this.publicKey = keyPair.getPublic();
    }

    @TargetApi(18)
    public void generateEd(String keyTag, boolean synchronizable, String label, Context context) throws Exception {
        String publicKeyB64 = Ed25519Helper.generateEd25519KeyPair(keyTag, label, context);
        // Store the public key for compatibility with existing API
        this.publicKey = null; // Ed25519 keys are stored separately
    }


    public boolean updatePrivateKey(String keyTag, String label, Context context) throws Exception {
        if (keyTag != null) {
            return Ed25519Helper.updateLabel(keyTag, label, context);
        }
        return false;
    }

    public String signEd(String message, String keyTag, Context context) throws Exception {
        return Ed25519Helper.sign(message, keyTag, context);
    }
    
    public boolean verifyEd(String signature, String message, String publicKey) throws Exception {
        return Ed25519Helper.verify(signature, message, publicKey);
    }
    
    public String getPublicKeyEd(String keyTag, Context context) throws Exception {
        return Ed25519Helper.getPublicKey(keyTag, context);
    }

    public String getCSR() throws IOException {
        byte  CSRder[] = this.csr.getEncoded();
        return dataToPem(CSR_HEADER, CSRder);
    }

}

