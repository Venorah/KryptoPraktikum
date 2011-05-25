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

  /**
   * Entschlüsselt den durch den FileInputStream <code>ciphertext</code> gegebenen Chiffretext und
   * schreibt den Klartext in den FileOutputStream <code>cleartext</code>.
   * <p>
   * Das blockweise Lesen des Chiffretextes soll mit der Methode {@link #readCipher readCipher}
   * durchgeführt werden, das blockweise Schreiben des Klartextes mit der Methode
   * {@link #writeClear writeClear}.
   * </p>
   * 
   * @param ciphertext
   *          Der FileInputStream, der den Chiffretext liefert.
   * @param cleartext
   *          Der FileOutputStream, in den der Klartext geschrieben werden soll.
   */
  public void decipher(FileInputStream ciphertext, FileOutputStream cleartext) {

  }

  /**
   * Verschlüsselt den durch den FileInputStream <code>cleartext</code> gegebenen Klartext und
   * schreibt den Chiffretext in den FileOutputStream <code>ciphertext</code>.
   * <p>
   * Das blockweise Lesen des Klartextes soll mit der Methode {@link #readClear readClear}
   * durchgeführt werden, das blockweise Schreiben des Chiffretextes mit der Methode
   * {@link #writeCipher writeCipher}.
   * </p>
   * 
   * @param cleartext
   *          Der FileInputStream, der den Klartext liefert.
   * @param ciphertext
   *          Der FileOutputStream, in den der Chiffretext geschrieben werden soll.
   */
  public void encipher(FileInputStream cleartext, FileOutputStream ciphertext) {

  }

  /**
   * Erzeugt einen neuen Schlüssel.
   * 
   * @see #readKey readKey
   * @see #writeKey writeKey
   */
  public void makeKey() {

    System.out.println("Dummy für die Schlüsselerzeugung.");
  }

  /**
   * Liest den Schlüssel mit dem Reader <code>key</code>.
   * 
   * @param key
   *          Der Reader, der aus der Schlüsseldatei liest.
   * @see #makeKey makeKey
   * @see #writeKey writeKey
   */
  public void readKey(BufferedReader key) {

  }

  /**
   * Schreibt den Schlüssel mit dem Writer <code>key</code>.
   * 
   * @param key
   *          Der Writer, der in die Schlüsseldatei schreibt.
   * @see #makeKey makeKey
   * @see #readKey readKey
   */
  public void writeKey(BufferedWriter key) {

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
  
  public static void example() {
    BigInteger p, b, c, secretKey;
    Random sc = new SecureRandom();
    secretKey = new BigInteger("12345678901234567890");
    //
    // public key calculation
    //
    System.out.println("secretKey = " + secretKey);
    p = BigInteger.probablePrime(64, sc);
    b = new BigInteger("3");
    c = b.modPow(secretKey, p);
    System.out.println("p = " + p);
    System.out.println("b = " + b);
    System.out.println("c = " + c);
    //
    // Encryption
    //
    System.out.println();
    System.out.println("Starting Encryption");
    String s = "234324839234";
    BigInteger X = new BigInteger(s);
    BigInteger r = new BigInteger(64, sc);
    BigInteger EC = X.multiply(c.modPow(r, p)).mod(p);
    BigInteger brmodp = b.modPow(r, p);
    System.out.println("Plaintext = " + X);
    System.out.println("r = " + r);
    System.out.println("EC = " + EC);
    System.out.println("b^r mod p = " + brmodp);
    //
    // Decryption
    //
    System.out.println();
    System.out.println("Starting Decryption");
    BigInteger crmodp = brmodp.modPow(secretKey, p);
    BigInteger d = crmodp.modInverse(p);
    BigInteger ad = d.multiply(EC).mod(p);
    System.out.println("\n\nc^r mod p = " + crmodp);
    System.out.println("d = " + d);
    System.out.println("Alice decodes: " + ad);
  }


}
