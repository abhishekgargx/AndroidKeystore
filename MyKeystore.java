
package com.abhishek.softneed;

import android.content.Context;
import android.security.KeyPairGeneratorSpec;
import android.util.Base64;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Calendar;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.security.auth.x500.X500Principal;


/*
 * AUTHOR : Abhishek Garg
 */

public class MyKeystore {

    private static KeyStore keyStore;

    //Keystore Alias Making
    private static void checkKeyStore(Context context) {

        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            // Create new key if needed
            if (!keyStore.containsAlias("Abhishek")) {
                Calendar start = Calendar.getInstance();
                Calendar end = Calendar.getInstance();
                end.add(Calendar.YEAR, 30);
                KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                        .setAlias(Constants.ALIAS)
                        .setSubject(new X500Principal("CN=AppName, O=Softneed"))
                        .setSerialNumber(BigInteger.ONE)
                        .setStartDate(start.getTime())
                        .setEndDate(end.getTime())
                        .build();
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
                generator.initialize(spec);

                KeyPair keyPair = generator.generateKeyPair();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    //Encryption
    public static String encryptString(Context context, String string_you_want_to_encrypt) {

        // CHECK IF KEYSTORE IS CREATED OR NOT
        checkKeyStore(context);

        try {
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("Abhishek", null);

            Cipher inCipher = Cipher.getInstance(Constants.PADDING_ALGO);

            inCipher.init(Cipher.ENCRYPT_MODE, privateKeyEntry.getCertificate().getPublicKey()); // public key

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, inCipher);

            cipherOutputStream.write(string_you_want_to_encrypt.getBytes());

            cipherOutputStream.close();

            byte[] vals = outputStream.toByteArray();

            String ENCRYPTED_KEY = Base64.encodeToString(vals, Base64.DEFAULT);

            //if code is encryption code does not generate exception for invalid key
            if(ENCRYPTED_KEY.equals("") || ENCRYPTED_KEY.equals(" ") || ENCRYPTED_KEY.isEmpty()){
                return null;
            }

            return ENCRYPTED_KEY;  // return encrypted key

        } catch (Exception e) {
            return null;
        }
    }


    //Decryption
    public static String decryptString(Context context ,  String string_you_want_to_decrypt) {

        // CHECK IF KEYSTORE IS CREATED OR NOT
        checkKeyStore(context);
        try {
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("Abhishek", null);

            Cipher output = Cipher.getInstance(Constants.PADDING_ALGO);
            output.init(Cipher.DECRYPT_MODE, privateKeyEntry.getPrivateKey()); //rsa private key

            //if key is blank
            if(string_you_want_to_decrypt.isEmpty()){
                return null;
            }

            CipherInputStream cipherInputStream = new CipherInputStream(
                    new ByteArrayInputStream(Base64.decode(string_you_want_to_decrypt, Base64.DEFAULT)), output);
            ArrayList<Byte> values = new ArrayList<>();
            int nextByte;
            while ((nextByte = cipherInputStream.read()) != -1) {
                values.add((byte) nextByte);
            }

            byte[] bytes = new byte[values.size()];
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = values.get(i);
            }

            String DECRYPTED_KEY = new String(bytes, 0, bytes.length, Constants.UTF);

            //if code is decryption code does not generate exception for invalid key
            if(DECRYPTED_KEY.equals("") || DECRYPTED_KEY.equals(" ") || DECRYPTED_KEY.isEmpty()){
                return null;
            }
            return DECRYPTED_KEY;  //Original decrypted String

        }catch (Exception e) {

            return null;
        }
    }


}
