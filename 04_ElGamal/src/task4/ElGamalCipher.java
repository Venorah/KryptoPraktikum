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
import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;
import de.tubs.cs.iti.jcrypt.chiffre.BlockCipher;
import de.tubs.cs.iti.jcrypt.chiffre.BlockCipherUtil;

/**
 * Dummy-Klasse für das ElGamal-Public-Key-Verschlüsselungsverfahren.
 * 
 * @author Martin Klußmann
 * @version 1.1 - Sat Apr 03 22:06:35 CEST 2010
 */
public final class ElGamalCipher extends BlockCipher {
  String keyString;

  // public key
  public BigInteger p;
  public BigInteger g;
  public BigInteger y;
  
  // private key
  public BigInteger x;

  public void makeKey() {
    Random sc = new SecureRandom();

    choosePrimeAndGenerator();

    // 1 <= x < p-1
    x = BigIntegerUtil.randomBetween(BigIntegerUtil.ONE, p.subtract(BigIntegerUtil.ONE), sc);

    y = fastExp(g, x, p);

    System.out.println("private key = " + x.toString());
    System.out.println("public key = (" + p.toString() + ", " + g.toString() + ", " + y.toString());

  }

  public void readKey(BufferedReader key) {
    try {

      keyString = new String(key.readLine()); // *

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

    BigInteger cipher = (p.multiply(C[1])).add(C[0]);

    writeCipher(ciphertext, cipher);

  }

  public void decipher(FileInputStream ciphertext, FileOutputStream cleartext) {

    //
    // // keyGenerator();
    //
    // BigInteger[] C = new BigInteger[] { a, b };
    // BigInteger M = decrypt(C);
    //
    // String outputString = new String(M.toByteArray());
    // System.out.println("Cipher Array: " + C[0] + " " + C[1]);
    // System.out.println("Clear: " + outputString);
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
    writeClear(cleartext, M);

  }

  public BigInteger randomPrime() {
    Random sc = new SecureRandom();
    // BigInteger q = new Big

    // return BigInteger.probablePrime(512, sc);
  }

  public BigInteger x() {
    return new BigInteger("12345678901234567890");
  }

  public BigInteger r(BigInteger k) {
    BigInteger r = g.modPow(k, p);

    return r;
  }

  public BigInteger s(BigInteger M, BigInteger r, BigInteger k_inverse) {
    BigInteger xr = x.multiply(r);
    BigInteger s = ((M.subtract(xr)).multiply(k_inverse)).mod(p.subtract(BigInteger.ONE));

    return s;
  }

  public BigInteger fastExp(BigInteger base, BigInteger exp, BigInteger mod) {
    BigInteger res = BigIntegerUtil.ONE;

    while (!exp.equals(BigIntegerUtil.ZERO)) {
      while ((exp.mod(BigIntegerUtil.TWO)).equals(BigIntegerUtil.ZERO)) {
        exp = exp.divide(BigIntegerUtil.TWO);
        base = base.multiply(base).mod(mod);
      }
      exp = exp.subtract(BigIntegerUtil.ONE);
      res = res.multiply(base).mod(mod);
    }
    System.out.println(base.toString() + "^" + exp.toString() + " mod " + exp.toString() + " = " + res);

    return res;
  }

  /**
   * fertig
   */
  public void choosePrimeAndGenerator() {
    Random sc = new SecureRandom();
    int k = 512; // prime number with k=512 bits
    int certainty = 100; // The probability that the new BigInteger represents a prime number will
                         // exceed (1-1/2^certainty)

    BigInteger q = null;
    p = null;
    do {
      q = new BigInteger(k - 1, certainty, sc);
      p = q.multiply(BigIntegerUtil.TWO).add(BigIntegerUtil.ONE); // secure prime p = 2q+1
    } while (!p.isProbablePrime(certainty));

    BigInteger factor, minusOne = null;
    g = null;
    do {
      // 2 <= g < p-1
      g = BigIntegerUtil.randomBetween(BigIntegerUtil.TWO, p.subtract(BigIntegerUtil.ONE), sc);

      factor = fastExp(g, q, p);
      minusOne = new BigInteger("-1", 10).mod(p);
    } while (factor != minusOne);
  }

  public void gammel(String message) {
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

    BigInteger M = message;
    BigInteger k = new BigInteger(512, sc);

    BigInteger a = g.modPow(k, p);
    BigInteger b = M.multiply(y.modPow(k, p)).mod(p);

    return new BigInteger[] { a, b };
  }

  public BigInteger decrypt(BigInteger[] C) {

    BigInteger a = C[0];
    BigInteger b = C[1];

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
