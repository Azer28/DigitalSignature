package com.signature;

import com.signature.exceptions.KeyGeneratorException;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Created by AzarM on 4/26/2018.
 */
public class KeyGenerator {
    public PrivateKey readPrivateKey(String privateKeyResourceName) {

        try (InputStream is = getClass().getClassLoader().getResourceAsStream(privateKeyResourceName)) {
            byte[] target = new byte[is.available()];
            is.read(target, 0, target.length);
            String res = new String(target);
            res = res.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----","").replace("\n", "");
            System.out.println(res);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(res));
            return kf.generatePrivate(spec);

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            //e.printStackTrace();
            throw new KeyGeneratorException("Exception on private key generation ", e);
        }
    }

    public PublicKey readPublicKey(String privateKeyResourceName ) {

        try (InputStream is = getClass().getClassLoader().getResourceAsStream(privateKeyResourceName)) {
            byte[] target = new byte[is.available()];
            is.read(target, 0, target.length);
            String res = new String(target);
            res = res.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replace("\n", "");
            System.out.println(res);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(res));
            PublicKey publicKey = keyFactory.generatePublic(spec);
            return publicKey;
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException  e) {
            e.printStackTrace();
            throw new KeyGeneratorException("Exception on public key generation", e);
        }
        //return null;

    }

    public static void main(String[] args) {
        //new com.signature.KeyGenerator().readPrivateKey("priv8.pem");
        new KeyGenerator().readPublicKey("public.pem");

    }
}
