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

import java.math.BigInteger;

import java.security.*;

import java.security.spec.*;

import java.util.Arrays;

import javax.crypto.*;

import javax.crypto.spec.*;

 

public class myServer {

 

    private Socket socket = null;

    private ServerSocket server = null;

    private DataInputStream streamIn = null;

    private DataOutputStream streamOut = null;

    private Key AESKey;

    private byte[] HMACkey;

    private byte[] hash;

 

    public myServer(int port, byte[] keyByte, PrivateKey keyBytes2) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InterruptedException {

        try {

            System.out.println("Binding to port " + port + ", please wait  ...");

            server = new ServerSocket(port);

            System.out.println("Server started: " + server);

            System.out.println("Waiting for a client ...");

            socket = server.accept();

            System.out.println("Client accepted: " + socket);

            open();

            boolean done = false;

            byte[] hashBytes = receiveLoginHash(); // calls the method receiveLoginHash and store the login hash as Hash bytes

            byte[] keyBytes = receivePublicKey(); // calls the method receivePublicKey and store the client public key into keyBytes

            boolean loginStatus = comparePasswordHash(hashBytes); // calls the method comparePasswordHash with the password hash of the client as parameter

            System.out.println("login status : " + loginStatus); // prints the login status

            if (loginStatus == false) { // if login status is false, closes all connection immediately

                close();

            }

            sendPublicKey(keyByte); // calling the function sendPublicKey to send the server public key to the client

            KeyFactory kf = KeyFactory.getInstance("DH"); // get instance of Diffie Hellman

            X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(keyBytes);

            PublicKey clientPublicKey = kf.generatePublic(x509Spec); // initialize clientPublicKey

            byte[] clientPKey = clientPublicKey.getEncoded(); // convert it to bytes

            System.out.println("Client public key: " + asHex(clientPKey)); // convert bytes into hex and print it out so we can read it

            KeyAgreement ka = KeyAgreement.getInstance("DH"); //getting instance of Key Agreement

            ka.init(keyBytes2); // initialize the key agreement with the server private key

            ka.doPhase(clientPublicKey, true); // add in the server public key

            byte[] secret = ka.generateSecret(); // generate the shared secret

            System.out.println("shared secret key:" + asHex(secret)); // print out the shared secret in hex format

            byte[] key = secret;

            MessageDigest sha = MessageDigest.getInstance("SHA-1"); //getting the instance of message digest

            key = sha.digest(key); // generating a hash from the shared secret

            key = Arrays.copyOf(key, 16);  // use only the first 128 bit of the hash as our AES key

            SecretKeySpec sessionKey = new SecretKeySpec(key, "AES"); // creating a new SecretKeySpec session. Parse in the key and the algorithm String name("AES")

            System.out.println("AES key: " + asHex(sessionKey.getEncoded())); // printing out the AES key in hex format

            HMACkey = sessionKey.getEncoded(); // getting the bytes of the sessionKey and storing it as HMACKey

            System.out.println("HMAC Key: " + asHex(HMACkey)); // print out the HMAC key in hex format

            AESKey = (Key) (sessionKey); // converting the SecretKeySpec sessionKey into Key AESKey

            while (!done) {

                try {

                    String line = streamIn.readUTF();

                    System.out.println("Encrypted message: " + line);

                    String decryptedMsg = decrypt(line); //calling the method decrypt to decrypt the encrypted message

                    boolean verify = verifyHash(decryptedMsg); // calling the method to regenerate the hash using the same hmac algorithm with the same key.If it matches, the data is not tempered with.

                    System.out.println("Message match: " + verify);

                    if (verify == true) {

                        System.out.println("Decrypted Message: " + decryptedMsg);

                        execCommands(decryptedMsg);

                    } else {

                        System.out.println("Closing connection.Hash does not match. MITM attack detected!"); // if the hash does not match the recomputed hash, the message has been tempered with

                        close();

                    }

                    done = decryptedMsg.equals("..bye"); // exits if ..bye is received

                } catch (IOException ioe) {

                    done = true;

 

                }

            }

            close();

        } catch (IOException ioe) {

            System.out.println(ioe);

        }

    }

 

    public void open() throws IOException {

        streamIn = new DataInputStream(new BufferedInputStream(socket.getInputStream()));

        streamOut = new DataOutputStream(socket.getOutputStream());

    }

 

    public void close() throws IOException {

        if (socket == null) {

            socket.close();

        }

        if (streamIn == null) {

            streamIn.close();

        }

        if (streamOut != null) {

            streamOut.close();

            System.out.println("stream closed");

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

 

    private String decrypt(String msg) {

        try {

            byte[] decryptedBase64 = Base64.decode(msg); // decode the base64 message

            byte[] decryptedMessage = Arrays.copyOfRange(decryptedBase64, 0, decryptedBase64.length - 32); // copying the encrypted Message out of the decryptedBase64 array into a new array called decryptedMessage

            int divisor = decryptedMessage.length / 16;    // mathematical formula to calculate the starting point and ending point of the hash

            int pos = 0;

            if (divisor == 1) {     // homemade mathematical formula to calculate the starting point and ending point of the hash depending on the size of the block of the encrypted AES message

                pos = 16;

            } else if (divisor == 2) {

                pos = 0;

            } else if (divisor >= 3) {

                pos = -16 * (divisor - 2);

            } else {

                System.out.println("Invalid pos");

            }

            hash = Arrays.copyOfRange(decryptedBase64, decryptedBase64.length - decryptedMessage.length - pos, decryptedBase64.length); // last 32 bytes of the message is the hash so we must copy it into a new array

            //System.out.println("encrypted AES length : "  + decryptedMessage.length);

            //System.out.println("hash length: " + hash.length);

            System.out.println("hash(hex format) : " + asHex(hash)); // print out the hash value of the message that we received

            System.out.println("encrypted AES: " + asHex(decryptedMessage));

            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // getting the instance of the cipher. Cipher mode: ECB/PKCS5Padding

            cipher.init(Cipher.DECRYPT_MODE, AESKey); //setting the cipher into DECRYPT_MODE

            byte[] decryptedMsg = cipher.doFinal(decryptedMessage); // decrypt the message with our AES key

            String decryptedMsgString = new String(decryptedMsg);  // cast decrypted message into String

            return decryptedMsgString; //return the decrypted message

        } catch (Exception e) {

            e.printStackTrace();

        }

        return null;

 

    }

 

    private boolean verifyHash(String msg) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

        boolean integrity = false;

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // getting the instance of the cipher. Cipher mode: ECB/PKCS5Padding

        cipher.init(Cipher.ENCRYPT_MODE, AESKey); //setting the cipher into ENCRYPT_MODE

        byte[] encryptedBytes = cipher.doFinal(msg.getBytes()); // getting the messsage bytes then encrypting it with our AES key

        Mac hmac = Mac.getInstance("HmacSHA256");   // getting instance of the HMAC

        hmac.init(new SecretKeySpec(HMACkey, "HmacSHA256"));  // initializing the HMAC

        byte[] messageHash = hmac.doFinal(encryptedBytes); // generating the hash

        //System.out.println("recompute hash: " + asHex(messageHash));

        if (Arrays.equals(hash, messageHash)) { // comparing the hash that we received and the one that we recompute.If both matches, the data are not tempered with.

            integrity = true;

        }

        return integrity;

    }

 

    public byte[] receivePublicKey() throws IOException {

        int length = streamIn.readInt();    // reads the length of the key

        byte[] keyBytes = new byte[length]; // create a byte to store the public key

        streamIn.readFully(keyBytes);  // read in the public key fully

        return keyBytes;

    }

 

    public void sendPublicKey(byte[] keyByte) throws IOException {

        streamOut.writeInt(keyByte.length); //send public key to server

        streamOut.write(keyByte); //send public key to server

    }

 

    public byte[] receiveLoginHash() throws IOException {

        int len = streamIn.readInt();    // reads the length of the key

        byte[] loginBytes = new byte[len]; // create a byte to store the public key

        streamIn.readFully(loginBytes);  // read in the public key fully

        return loginBytes;

    }

 

    public boolean comparePasswordHash(byte[] passHash) {

        boolean login = false;

        String storedHash = "34383839363234336338333033333237663665333764653332343439343161303761396631396139623332616630623339313061616233326538346332643161"; // the stored password hash of the client

        if (asHex(passHash).equals(storedHash)) { // comparing the hash that we received and the one that we recompute.If both matches, the data are not tempered with.

            login = true;

        }

        return login; // return the login status

    }

 

    public void execCommands(String decodedMsg) throws InterruptedException { // Advance feature: execute command on the server

        try {

            Runtime rt = Runtime.getRuntime();  // getting runtime

            String cmd[] = {"cmd.exe", "/C", decodedMsg}; // this is the command that will be executed

            Process p = rt.exec(cmd); // execute the command

            p.waitFor();

            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream())); // creating new BufferedReader reader

            String command = reader.readLine(); // store the results into string command

            while (command != null) {  // while the command is not null

                System.out.println(command); // print out the results

               command = reader.readLine();

            }

        } catch (IOException e1) {

            System.out.println(e1); // printing out IOException

        } catch (InterruptedException e2) {

            System.out.println(e2); // printing InterruptedException

        }

    }

 

    public static void main(String args[]) throws Exception {

        myServer server = null;

        if (args.length != 1) {

        System.out.println("Usage: java myServer port");

        } else {

        KeyPairGenerator kg = KeyPairGenerator.getInstance("DH"); // getting instance of keypair generator

        kg.initialize(1024);  // initializing the keypair generator

        KeyPair kpair = kg.genKeyPair(); //generates  a keypair

        PrivateKey priKey = kpair.getPrivate(); // gets the private key from the key pair

        PublicKey pubKey = kpair.getPublic(); // gets the public key from the key pair

        byte[] keyByte = pubKey.getEncoded();   // converts/encoded it into bytes so it can be read

        //System.out.println("My pub key: " + asHex(keyByte));

        server = new myServer(Integer.parseInt(args[0]), keyByte, priKey);

        }

    }

}

 