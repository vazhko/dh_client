//package client;
import javax.xml.bind.DatatypeConverter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Crypter {
    private static final int AES_KEY_SIZE = 128;
    private static final int DH_KEY_SIZE = 1024;

    private static KeyPairGenerator keyPairGenerator;
    private static KeyFactory keyFactory;

    private static KeyAgreement keyAgreement;
    private static MessageDigest sha256;

    private static Cipher cipherAES;
    
    private PublicKey serverPublicKey;
    private PrivateKey clientPrivateKey;
    private PublicKey clientPublicKey;

    
    private SecretKey clientAESKey;
    static {
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("DH");
            keyPairGenerator.initialize(DH_KEY_SIZE);

            keyAgreement = KeyAgreement.getInstance("DH");
            sha256 = MessageDigest.getInstance("SHA-256");

            keyFactory = KeyFactory.getInstance("DH");

            cipherAES = Cipher.getInstance("AES/ECB/PKCS5Padding");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void setClientPrivateKey(PrivateKey clientPrivateKey) {
        this.clientPrivateKey = clientPrivateKey;
    }

    public PrivateKey getClientPrivateKey() {
        return clientPrivateKey;
    }

    public void setClientPublicKey(PublicKey clientPublicKey) {
        this.clientPublicKey = clientPublicKey;
    }

    public PublicKey getClientPublicKey() {
        return clientPublicKey;
    }
    
    public PublicKey getServerPublicKey() {
        return serverPublicKey;
    }

    public synchronized int generateClientKeys() {
        int crypterError = 0;

        try {

            KeyPair clientKeyPair = keyPairGenerator.genKeyPair();
            clientPrivateKey = clientKeyPair.getPrivate();
            clientPublicKey = clientKeyPair.getPublic();
            //byte[] bkeyCliPub = Arrays.copyOf(sha256.digest(secretDevice), AES_KEY_SIZE / Byte.SIZE);
            String hex = DatatypeConverter.printHexBinary(clientPublicKey.getEncoded());
            System.out.println(hex);
            

        } catch (Exception e) {
            crypterError = 2;
            e.printStackTrace();
        }

        return crypterError;
    }
    
    private int GenerateAESKeys() {
           int crypterError = 0;
           try {

               if (clientPrivateKey != null && serverPublicKey != null) {
                   //AES key
                   keyAgreement.init(clientPrivateKey);
                   keyAgreement.doPhase(serverPublicKey, true);

                   byte[] secretDevice = keyAgreement.generateSecret();
                   
                   String hex = DatatypeConverter.printHexBinary(secretDevice);
                   System.out.println("secretDevice=");
                   System.out.println(hex);
                   System.out.println("");

                   
                   byte[] bkeyDevice = Arrays.copyOf(sha256.digest(secretDevice), AES_KEY_SIZE / Byte.SIZE);
                   hex = DatatypeConverter.printHexBinary(bkeyDevice);
                   System.out.println(hex);
                   
                   clientAESKey = new SecretKeySpec(bkeyDevice, "AES");
               }

           } catch (Exception e) {
               crypterError = 2;
               e.printStackTrace();
           }

           return crypterError;
       }
    public synchronized int setServerPublicKey(byte[] data) {
           int crypterError = 0;
           
           String hex = DatatypeConverter.printHexBinary(data);
           System.out.println("input=");
           System.out.println(hex);
           System.out.println("");

           try {
               this.serverPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(data));
               crypterError = GenerateAESKeys();
           } catch (Exception e) {
               crypterError = 2;
               e.printStackTrace();
           }

           return crypterError;
       }
    public synchronized byte[] encryptDataAtClient(byte[] data, int where, int length) {

           byte[] cryptedData = null;

           try {        	   
               cipherAES.init(Cipher.ENCRYPT_MODE, clientAESKey);
               /*
               byte[] cryptedUpdate = cipherAES.update(data, where, length);
               byte[] cryptedFinal = cipherAES.doFinal();
               cryptedData = new byte[cryptedUpdate.length + cryptedFinal.length];
               System.arraycopy(cryptedUpdate, 0, cryptedData, 0, cryptedUpdate.length);
               System.arraycopy(cryptedFinal, 0, cryptedData, cryptedUpdate.length, cryptedFinal.length);
               */
               String plainText = "Ura!!!!!";
               return cipherAES.doFinal(plainText.getBytes());
           } catch (Exception e) {
               e.printStackTrace();
           }

           return cryptedData;
       }
    public synchronized byte[] decryptDataAtClient(byte[] data, int where, int length) {

          byte[] decryptedData = null;

          try {
              cipherAES.init(Cipher.DECRYPT_MODE, clientAESKey);
          /* 
              byte[] decryptedUpdate = cipherAES.update(data, where, length);
              byte[] decryptedFinal = cipherAES.doFinal();
              if (decryptedFinal == null) {
                  decryptedFinal = new byte[0];
              }
              decryptedData = new byte[decryptedUpdate.length + decryptedFinal.length];
              System.arraycopy(decryptedUpdate, 0, decryptedData, 0, decryptedUpdate.length);
              System.arraycopy(decryptedFinal, 0, decryptedData, decryptedUpdate.length, decryptedFinal.length);
          */
              return cipherAES.doFinal(data);
          } catch (Exception e) {
              e.printStackTrace();
          }

          return decryptedData;
      }

    public static void main(String[] args) throws IOException {
        Crypter clientCrypter = new Crypter();
        clientCrypter.generateClientKeys();
        System.out.println("" +clientCrypter.getClientPublicKey() );
        System.out.println("" +clientCrypter.getClientPrivateKey().toString() );

        
        byte[] bytes = clientCrypter.getClientPrivateKey().getEncoded();
        //String hex = DatatypeConverter.printHexBinary(bytes);
        byte[] bytes2 = new byte[64]; 
        System.arraycopy(bytes, bytes.length - bytes2.length, bytes2, 0, bytes2.length);
        
        String hex = DatatypeConverter.printHexBinary(bytes2);
        System.out.println(hex); // prints "7F0F00"
        
        //clientCrypter.setServerPublicKey( Files.readAllBytes(Paths.get("d:\\Technical_doc\\prj\\java\\test_server\\bin\\server_pub.bin", args)));
        clientCrypter.setServerPublicKey(Files.readAllBytes(Paths.get("d:\\Technical_doc\\prj\\Lottery\\Server\\server\\HexDecode.bin", args)));
        //String data_from_file = readFileToString(Paths.get("d:\\Technical_doc\\prj\\java\\test_server\\server_pub.txt", args));
        //byte[] encoded = Files.readAllBytes(Paths.get("d:\\Technical_doc\\prj\\java\\test_server\\server_pub.bin", args));
        //String data_from_file = readFile("d:\\Technical_doc\\prj\\java\\test_server\\server_pub.txt", StandardCharsets.US_ASCII);
        //System.out.println("" +clientCrypter.getServerPublicKey());
        //String content = new String ( Files.readAllBytes( Paths.get("d:\\Technical_doc\\prj\\java\\test_server\\server_pub.txt", args)));
        

        
        byte[] Data = {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7};
        byte[] encrypted = clientCrypter.encryptDataAtClient(Data, 0, 32);
        hex = DatatypeConverter.printHexBinary(encrypted);
        System.out.println("encrypt" );
        System.out.println(hex );        
        byte[] decrypted = clientCrypter.decryptDataAtClient(encrypted, 0, 32+16); 
        //System.out.println("" +decrypted );
        hex = DatatypeConverter.printHexBinary(decrypted);
        System.out.println("decrypt" );
        System.out.println(hex); // prints "7F0F00"
        
        
        //decryptDataAtClient
    }
}
