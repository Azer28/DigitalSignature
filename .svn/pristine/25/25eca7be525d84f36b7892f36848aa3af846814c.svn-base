package com.signature;

import com.signature.exceptions.*;
import com.signature.exceptions.RSASignatureException;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Created by AzarM on 4/26/2018.
 */
public class RSASignature {

    private KeyGenerator generator = new KeyGenerator();

    public String sign(byte[] dataToBeSigned) {
        try {
            PrivateKey privateKey = generator.readPrivateKey("priv8.pem");
            Signature sign = Signature.getInstance("SHA1withRSA");
            sign.initSign(privateKey);
            sign.update(dataToBeSigned);
            byte[] ds = sign.sign();
            String signedBase64EncodedData = DatatypeConverter.printBase64Binary(ds);
            return signedBase64EncodedData;
        } catch (NoSuchAlgorithmException | InvalidKeyException | java.security.SignatureException e) {
            e.printStackTrace();
            throw new RSASignatureException(String.format(" Exception thrown on signing message %s",
                    new String(dataToBeSigned)), e);
        }
    }

    public String sign(String dataToBeSigned) {
        try {
            return sign(dataToBeSigned.getBytes("UTF8"));
        } catch (UnsupportedEncodingException e) {
            throw new RSASignatureException(" Exception thrown on signing message ", e);
        }
    }

    public boolean verify(byte[] plainMessage, String encodedMessage) {
        try {
            Signature signature = Signature.getInstance("SHA1withRSA");
            PublicKey publicKey = generator.readPublicKey("public.pem");
            signature.initVerify(publicKey);
            signature.update(plainMessage);
            return signature.verify(Base64.getDecoder().decode(encodedMessage.getBytes("UTF8")));
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | UnsupportedEncodingException e ) {
            e.printStackTrace();
            throw new RSASignatureException(String.format(" Exception on verifying plainMessage %s and encodedMessage  ",
                    new String(plainMessage), encodedMessage) , e);
        }
    }

    public boolean verify(String plainMessage, String encodedMessage) {
        try {
            return verify(plainMessage.getBytes("UTF8"), encodedMessage);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            throw new RSASignatureException("Exception on string to byte conversion", e);
        }
    }

    public static void main(String[] args) throws UnsupportedEncodingException {
        RSASignature obj = new RSASignature();
        String s = obj.sign( "<request point = \"273\"><menu/></request>");

        String plainMessage = "<response><result code=\"0\">\n" +
                "<folder id=\"3193\" name=\"Services\" img=\"\" order=\"0\">\n" +
                "<service id=\"405\" code=\"402\" name=\"Baktelecom.az\" img=\"baktelecomaz.png\" order=\"0\" commission=\"0 %\" maxsum=\"80000\" minsum=\"1\" hotkey=\"0\" handlerType=\"AdvancedProvider\" />\n" +
                "<service id=\"427\" code=\"427\" name=\"Az&#601;riqaz &#304;B\" img=\"azerigas.png\" order=\"1\" commission=\"0 %\" maxsum=\"1500000\" minsum=\"100\" hotkey=\"0\" handlerType=\"AdvancedProvider\" />\n" +
                "<service id=\"463\" code=\"463\" name=\"TransEuroCom (Internet)\" img=\"transeurocom.png\" order=\"2\" commission=\"0 %\" maxsum=\"1000000\" minsum=\"10\" hotkey=\"0\" handlerType=\"AdvancedProvider\" />\n" +
                "<service id=\"349\" code=\"349\" name=\"Embafinans\" img=\"bank/embaflogo.png\" order=\"3\" commission=\"0 %\" maxsum=\"500000\" minsum=\"100\" hotkey=\"0\" handlerType=\"UniversalProvider\" />\n" +
                "<service id=\"238\" code=\"238\" name=\"Kapital Bank\" img=\"bank/kapbank.png\" order=\"3\" commission=\"0 %\" maxsum=\"1000000\" minsum=\"100\" hotkey=\"0\" handlerType=\"AdvancedProvider\" />\n" +
                "</folder>\n" +
                "</result></response>";
        boolean k = obj.verify(plainMessage.getBytes("UTF-8"), "VU2++15RZNouycL2Aa/iUwFqCTaozn4KhQU/dlJ1hzE9wH6NiU/eh0UEx4GhLcLideqJtOhC/Hr6WFCsq5dMuvgDsvozcMbvZUQzTD3zVrzzWOVGzewv3pATwKUzDMvHuBRVlJuaDaKBtrWixFwEDliE/1XQW0TmXKRlxHVcwE0WIla/D9uboSRKHrbqslH4g8FVZ9hW03mu+rDiYWpnu80nJu6xu+G0YQ9F5h/1O8ID09vi6l/z7IWgI+CXNzv0GDfCoBvolXCm0v5PkEJNdlC+SNfQtFA36RywZJKMUnSVaARXRTlzYv1CQSeD0kzj00xnu6b7JG/1vvJ3vKz0Mg==");
        System.out.println(k);
        System.out.println(s);


    }
}
