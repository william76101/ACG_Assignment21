/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author William_Standard
 */
    


import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

import java.net.*;

import java.io.*;

import java.security.InvalidKeyException;

import java.security.Key;

import java.security.KeyFactory;

import java.security.KeyPair;

import java.security.KeyPairGenerator;

import java.security.MessageDigest;

import java.security.NoSuchAlgorithmException;

import java.security.PrivateKey;

import java.security.PublicKey;

import java.security.Timestamp;

import java.security.spec.InvalidKeySpecException;

import java.security.spec.X509EncodedKeySpec;

import java.util.Arrays;

import java.util.Calendar;

import java.util.Date;

import javax.crypto.BadPaddingException;

import javax.crypto.Cipher;

import javax.crypto.IllegalBlockSizeException;

import javax.crypto.KeyAgreement;

import javax.crypto.Mac;

import javax.crypto.NoSuchPaddingException;

import javax.crypto.spec.IvParameterSpec;

import javax.crypto.spec.SecretKeySpec;

    
    public class myClient {

        private Socket socket = null;

        private DataInputStream console = null;

        private DataInputStream console2 = null;

        private DataOutputStream streamOut = null;

        private Key AESKey;

        private byte[] HMACkey;
        
        
        
         public myClient(String serverName, int serverPort, byte[] keyBytes, PrivateKey keyBytes2) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException {

        System.out.println("Establishing connection. Please wait ...");

        try {

            socket = new Socket(serverName, serverPort);

            System.out.println("Connected: " + socket);

            start();

            sendPasswordHash();

            sendPublicKey(keyBytes); // calls the method sendPublicKey. The parameter is keyBytes which is the client Public Key

            byte[] serverkeyByte = receivePublicKey(); // calls the method receivePublicKey and store the server public key bytes into byte [] serverkeyByte

            byte[] key = generateSharedSecret(serverkeyByte, keyBytes2); //calls the methodd generateSharedSecret. Parse in the client private key as parameter

            SecretKeySpec sessionKey = deriveAESKey(key); // call the method deriveAESKey and storing the aes key into session key

            System.out.println("AES key: " + asHex(sessionKey.getEncoded())); // print out the AES key in hex format

            HMACkey = sessionKey.getEncoded(); // getting the bytes of the sessionKey and storing it into byte [] HMACKey
            
            

            System.out.println("HMAC Key: " + asHex(HMACkey)); // print out the HMAC key in hex format

            AESKey = (Key) (sessionKey); // casting the SecretKeySpec sessionKey into Key test

        } catch (UnknownHostException uhe) {

            System.out.println("Host unknown: " + uhe.getMessage());

        } catch (IOException ioe) {

            System.out.println("Unexpected exception: " + ioe.getMessage());

        }

        String line = "";

        while (!line.equals("..bye")) {

            try {

                line = console2.readLine();  // read in the line the user inputs

                String encryptedMsg = encrypt(line);  //calling the method encrypt and storing the encrypted message into String encryptedMsg

                System.out.println("encrypted msg: " + encryptedMsg); // printing out the encrypted message

                streamOut.writeUTF(encryptedMsg); //sending the message to the server

                streamOut.flush();

            } catch (IOException ioe) {

                System.out.println("Sending error: " + ioe.getMessage());

            }

        }

    }

 

    public void start() throws IOException {

        console = new DataInputStream(new BufferedInputStream(socket.getInputStream())); //read public key

        console2 = new DataInputStream(System.in);

        streamOut = new DataOutputStream(socket.getOutputStream());

    }

 

    public void stop() {

        try {

            if (console != null) {

                console.close();

            }

            if (console2 != null) {

                console2.close();

            }

            if (streamOut != null) {

                streamOut.close();

                System.out.println("stream closed");

            }

            if (socket != null) {

                socket.close();

            }

        } catch (IOException ioe) {

            System.out.println("Error closing ...");

        }

    }

 

    public static String asHex(byte buf[]) {

 

        //Obtain a StringBuffer object

        StringBuffer strbuf = new StringBuffer(buf.length * 2);

        int i;

 

        for (i = 0; i < buf.length; i++) {

            if (((int) buf[i] & 0xff) < 0x10) {

                strbuf.append("0");

            }

            strbuf.append(Long.toString((int) buf[i] & 0xff, 16));

        }

        // Return result string in Hexadecimal format

        return strbuf.toString();

    }

 

    public String encrypt(String msg) {

        try {

            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // getting the instance of the cipher. Cipher mode: ECB/PKCS5Padding

            cipher.init(Cipher.ENCRYPT_MODE, AESKey); //setting the cipher into ENCRYPT_MODE

            byte[] encryptedBytes = cipher.doFinal(msg.getBytes()); // getting the messsage bytes then encrypting it with our AES key

            System.out.println("Encrypted AES message " + asHex(encryptedBytes));

            Mac hmac = Mac.getInstance("HmacSHA256");  // getting instance of the HMAC

            hmac.init(new SecretKeySpec(HMACkey, "HmacSHA256")); // initializing the HMAC

            byte[] messageHash = hmac.doFinal(encryptedBytes); // generating a hash of the message and saving it into the byte [] signature

            byte[] cipherBytes = new byte[encryptedBytes.length + messageHash.length];

            // copy mac into end of destination (from pos encryptedBytes.length, copy messageHash.length)

            System.arraycopy(encryptedBytes, 0, cipherBytes, 0, encryptedBytes.length);

            System.arraycopy(messageHash, 0, cipherBytes, encryptedBytes.length, messageHash.length); // append the HMAC into the last 32 bytes of the byte [] cipherBytes

            String encryptedString = Base64.encode(cipherBytes); // encoded the encrypted message with base64

            return encryptedString;

 

        } catch (Exception e) {

            e.printStackTrace();

        }

        return null;

 

    }

 

    public void sendPasswordHash() throws IOException {

        String salt = "[B@307c197e"; // declaring the salt.

        String passwordToHash = "yandao96"; // the password of the client

        String loginHash = null;

        try {                                            // computes the hash

            MessageDigest md = MessageDigest.getInstance("SHA-256");

            md.update(salt.getBytes());

            byte[] bytes = md.digest(passwordToHash.getBytes());

            StringBuilder sb = new StringBuilder();

            for (int i = 0; i < bytes.length; i++) {

                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));

            }

            loginHash = sb.toString();

        } catch (NoSuchAlgorithmException e) {

            e.printStackTrace();

        }

        byte[] login = loginHash.getBytes();

        streamOut.writeInt(login.length); //send public key to server

        streamOut.write(login);  // send public key to server

    }

 

    public void sendPublicKey(byte keyBytes[]) throws IOException {

        streamOut.writeInt(keyBytes.length); //send public key to server

        streamOut.write(keyBytes);  // send public key to server

    }

 

    public byte[] receivePublicKey() throws IOException {

        int length = console.readInt();    // reads the length of the key

        byte[] serverkeyByte = new byte[length]; // create a byte to store the public key

        console.readFully(serverkeyByte);  // read in the public key fully

        return serverkeyByte; // return the server public key

    }

 

    public byte[] generateSharedSecret(byte[] serverkeyByte, PrivateKey clientPrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {

        KeyFactory kf = KeyFactory.getInstance("DH"); // get instance of Diffie Hellman

        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(serverkeyByte);

        PublicKey serverPublicKey = kf.generatePublic(x509Spec); // initialize serverPublicKey

        byte[] serverPKey = serverPublicKey.getEncoded(); // convert it to bytes

        System.out.println("Server public key: " + asHex(serverPKey)); // convert bytes into string so we can read it

        KeyAgreement ka = KeyAgreement.getInstance("DH"); //getting instance of Key Agreement

        ka.init(clientPrivateKey); // initialize the key agreement with the client private key

        ka.doPhase(serverPublicKey, true); // add in the server public key

        byte[] secret = ka.generateSecret(); // generate the secret key

        System.out.println("shared secret key:" + asHex(secret)); // print out the shared secret in hex format

        return secret; // return the shared secret

    }

 

    public SecretKeySpec deriveAESKey(byte[] key) throws NoSuchAlgorithmException {

        MessageDigest sha = MessageDigest.getInstance("SHA-1"); //getting the instance of message digest

        key = sha.digest(key);  // generating a hash from the shared secret

        key = Arrays.copyOf(key, 16); // use only the first 128 bit of the hash as our AES key

        SecretKeySpec sessionKey = new SecretKeySpec(key, "AES"); // creating a new SecretKeySpec session. Parse in the key and the algorithm String name("AES")

        return sessionKey;

    }

 

    public static void main(String args[]) throws Exception {

        myClient client = null;

        if (args.length != 2) {

            System.out.println("Usage: java myClient host port");

        } else {

            KeyPairGenerator kg = KeyPairGenerator.getInstance("DH"); // getting instance of keypair generator

            kg.initialize(1024); // initializing the keypair generator

            KeyPair kpair = kg.genKeyPair();  //generates  a keypair

            PrivateKey priKey = kpair.getPrivate(); // gets the private key from the key pair

            PublicKey pubKey = kpair.getPublic(); // gets the public key from the key pair

            byte[] keyBytes = pubKey.getEncoded();  // converts/encoded it into bytes so it can be read

            System.out.println("My pub key: " + asHex(keyBytes));

            client = new myClient(args[0], Integer.parseInt(args[1]), keyBytes, priKey);

        }

    }

}