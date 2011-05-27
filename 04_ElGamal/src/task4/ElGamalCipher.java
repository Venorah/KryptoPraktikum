/*
 * jCrypt - Programmierumgebung für das Kryptologie-Praktikum
 * Studienarbeit am Institut für Theoretische Informatik der
 * Technischen Universität Braunschweig
 * 
 * Datei:        ElGamalCipher.java
 * Beschreibung: Dummy-Implementierung der ElGamal-Public-Key-Verschlüsselung
 * Erstellt:     30. März 2010
 * Autor:        Martin Klußmann
 */

package task4;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import de.tubs.cs.iti.jcrypt.chiffre.BlockCipher;

/**
 * Dummy-Klasse für das ElGamal-Public-Key-Verschlüsselungsverfahren.
 * 
 * @author Martin Klußmann
 * @version 1.1 - Sat Apr 03 22:06:35 CEST 2010
 */
public final class ElGamalCipher extends BlockCipher {

  String keyString;
  
  public BigInteger[] pub;
  public BigInteger priv;

  public void makeKey() {

  }

  public void readKey(BufferedReader key) {
    try {

      keyString = new String(key.readLine()); //*

      Logger("Reading Information: ");
      Logger("+--KeyString: " + keyString);

      key.close();
    } catch (IOException e) {
      System.err.println("Abbruch: Fehler beim Lesen oder Schließen der " + "Schlüsseldatei.");
      e.printStackTrace();
      System.exit(1);
    } catch (NumberFormatException e) {
      System.err.println("Abbruch: Fehler beim Parsen eines Wertes aus der " + "Schlüsseldatei.");
      e.printStackTrace();
      System.exit(1);
    }
  }

  public void writeKey(BufferedWriter key) {
    try {
      key.write(keyString);

      Logger("Writing Information: ");
      Logger("+--Key: " + keyString);

      key.close();
    } catch (IOException e) {
      System.out.println("Abbruch: Fehler beim Schreiben oder Schließen der " + "Schlüsseldatei.");
      e.printStackTrace();
      System.exit(1);
    }
  }

  public void encipher(FileInputStream cleartext, FileOutputStream ciphertext) {

    keyGenerator();

    String message = getTextAsString(cleartext);
    BigInteger M = new BigInteger(message.getBytes());
    
    BigInteger[] C = encrypt(M);

    String outputString = C[0].toString() + " " + C[1].toString();
    
    System.out.println("message: " + message);
    System.out.println("M: " + M);
    System.out.println("Cipher: " + outputString);

    try {
      ciphertext.write(outputString.getBytes());
    } catch (IOException e1) {
      System.out.println("Failed at FileOutputStream");
      e1.printStackTrace();
    }

    try {
      cleartext.close();
      ciphertext.close();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  public void decipher(FileInputStream ciphertext, FileOutputStream cleartext) {

//    keyGenerator();

    String cipherTextString = getTextAsString(ciphertext);
    String[] cipherStringArray = cipherTextString.split(" ");

    BigInteger[] C = new BigInteger[] { new BigInteger(cipherStringArray[0]), new BigInteger(cipherStringArray[1]) };
    BigInteger M = decrypt(C);

    String outputString = new String(M.toByteArray());
    System.out.println("Cipher: " + cipherTextString);
    System.out.println("Cipher Array: " + C[0] + " " + C[1]);
    System.out.println("Clear: " + outputString);


    try {
      cleartext.write(outputString.getBytes());
    } catch (IOException e1) {
      System.out.println("Failed at FileOutputStream");
      e1.printStackTrace();
    }

    try {
      cleartext.close();
      ciphertext.close();
    } catch (IOException e) {
      e.printStackTrace();
    }

  }

  public BigInteger Fastexp(BigInteger base, BigInteger exp, BigInteger n) {
    BigInteger res = BigInteger.ONE;
    BigInteger TWO = new BigInteger("2", 10);

    while (!exp.equals(BigInteger.ZERO)) {
      while ((exp.mod(TWO)).equals(BigInteger.ZERO)) {
        exp = exp.divide(TWO);
        base = base.multiply(base).mod(n);
      }
      exp = exp.subtract(BigInteger.ONE);
      res = res.multiply(base).mod(n);
    }
    System.out.println(base.toString() + "^" + exp.toString() + " mod " + exp.toString() + " = " + res);

    return res;
  }

  public BigInteger p() {
    Random sc = new SecureRandom();
    return BigInteger.probablePrime(512, sc);
  }

  public BigInteger x() {
    return new BigInteger("12345678901234567890");
  }

  public void keyGenerator() {

    BigInteger p = p();
    BigInteger g = new BigInteger("3");  //TODO
    BigInteger x = x();
    BigInteger y = g.modPow(x, p);

    priv = x;
    pub = new BigInteger[] { p, g, y };
  }
  
  public void gammel(String message){
    keyGenerator();

    // message.length <= 8 . Wenn groesser als 8, dann kommt
    // was falsches raus o.O
    BigInteger M = new BigInteger(message.getBytes());
    BigInteger[] C = encrypt(M);
    
    BigInteger M2 = decrypt(C);
    
    String output = new String(M2.toByteArray());
    System.out.println("Clear: " + output);
  }

  public BigInteger[] encrypt(BigInteger message) {
    Random sc = new SecureRandom();

    BigInteger p = pub[0];
    BigInteger g = pub[1];
    BigInteger y = pub[2];

    BigInteger M = message;
    BigInteger k = new BigInteger(512, sc);

    BigInteger a = g.modPow(k, p);
    BigInteger b = M.multiply(y.modPow(k, p)).mod(p);

    return new BigInteger[] { a, b };
  }

  public BigInteger decrypt(BigInteger[] C) {

    BigInteger a = C[0];
    BigInteger b = C[1];

    BigInteger p = pub[0];
    BigInteger x = priv;

    BigInteger exponent = (p.subtract(x)).subtract(new BigInteger("1"));
    BigInteger z = a.modPow(exponent, p);
    BigInteger M = (z.multiply(b)).mod(p);

    return M;
  }
  
  public static String getTextAsString(FileInputStream cleartext) {
    StringBuffer clearTextBuffer = new StringBuffer();

    try {
      int ch = 0;
      while ((ch = cleartext.read()) != -1) {
        clearTextBuffer.append((char) ch);
      }
    } catch (IOException e) {
      e.printStackTrace();
    }

    return clearTextBuffer.toString();
  }
  
  private void Logger(String event) {
    System.out.println("ElGamal$  " + event);
  }

}
