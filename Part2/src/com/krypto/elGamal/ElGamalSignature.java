/*
 * jCrypt - Programmierumgebung für das Kryptologie-Praktikum
 * Studienarbeit am Institut für Theoretische Informatik der
 * Technischen Universität Braunschweig
 * 
 * Datei:        ElGamalSignature.java
 * Beschreibung: Dummy-Implementierung des ElGamal-Public-Key-Signaturverfahrens
 * Erstellt:     30. März 2010
 * Autor:        Martin Klußmann
 */

package com.krypto.elGamal;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;
import de.tubs.cs.iti.jcrypt.chiffre.Signature;

/**
 * Dummy-Klasse für das ElGamal-Public-Key-Signaturverfahren.
 * 
 * @author Martin Klußmann
 * @version 1.1 - Sat Apr 03 22:14:47 CEST 2010
 */
public final class ElGamalSignature extends Signature {
  String publicKey;
  String privateKey;
  String publicKeyFile;
  String privateKeyFile;

  // public key
  public BigInteger p;
  public BigInteger g;
  public BigInteger y;

  // private key
  public BigInteger x;
  
  public ElGamalSignature(BigInteger p, BigInteger g, BigInteger y, BigInteger x){
    this.p = p;
    this.g = g;
    this.y = y;
    this.x = x;
  }

  /**
   * Erzeugt einen neuen Schlüssel.
   * 
   * @see #readKey readKey
   * @see #writeKey writeKey
   */
  public void makeKey() {
    Random sc = new SecureRandom();

    getPrimeAndGenerator();

    // private key 1 <= x < p-1
    x = BigIntegerUtil.randomBetween(BigIntegerUtil.ONE, p.subtract(BigIntegerUtil.ONE), sc);

    y = g.modPow(x, p);

    privateKey = p.toString() + "\n" + g.toString() + "\n" + x.toString();
    publicKey = p.toString() + "\n" + g.toString() + "\n" + y.toString();

    System.out.println("private key = " + privateKey);
    System.out.println("public key = (" + publicKey + ")");
  }

  public void getPrimeAndGenerator() {
    Random sc = new SecureRandom();
    int k = 512; // prime number with k=512 bits
    int certainty = 100; // The probability that the new BigInteger represents a prime number will
                         // exceed (1-1/2^certainty)

    p = null;
    BigInteger q = null;
    do {
      q = new BigInteger(k - 1, certainty, sc);
      p = q.multiply(BigIntegerUtil.TWO).add(BigIntegerUtil.ONE); // secure prime p = 2q+1
    } while (!p.isProbablePrime(certainty));

    BigInteger MINUS_ONE = BigInteger.ONE.negate().mod(p); // -1 mod p

    g = null;
    BigInteger factor = null;
    do {
      // 2 <= g < p-1
      g = BigIntegerUtil.randomBetween(BigIntegerUtil.TWO, p.subtract(BigIntegerUtil.ONE), sc);
      factor = g.modPow(q, p);
    } while (!factor.equals(MINUS_ONE));
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
    try {
      publicKeyFile = key.readLine();
      privateKeyFile = key.readLine();

      BufferedReader reader = null;
      try {
        reader = new BufferedReader(new FileReader(publicKeyFile));

        // pubkey
        p = new BigInteger(reader.readLine());
        g = new BigInteger(reader.readLine());
        y = new BigInteger(reader.readLine());

        publicKey = p.toString() + "\n" + g.toString() + "\n" + y.toString();
      } catch (FileNotFoundException e) {
        e.printStackTrace();
      }
      try {
        reader = new BufferedReader(new FileReader(privateKeyFile));

        // privatekey
        p = new BigInteger(reader.readLine());
        g = new BigInteger(reader.readLine());
        x = new BigInteger(reader.readLine());

        privateKey = p.toString() + "\n" + g.toString() + "\n" + x.toString();
      } catch (FileNotFoundException e) {
        e.printStackTrace();
      }

      Logger("Reading Information: ");
      Logger("+--publicKey: " + publicKey);
      Logger("+--privateKey: " + privateKey);

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

  /**
   * Signiert den durch den FileInputStream <code>cleartext</code> gegebenen Klartext und schreibt
   * die Signatur in den FileOutputStream <code>ciphertext</code>.
   * <p>
   * Das blockweise Lesen des Klartextes soll mit der Methode {@link #readClear readClear}
   * durchgeführt werden, das blockweise Schreiben der Signatur mit der Methode {@link #writeCipher
   * writeCipher}.
   * </p>
   * 
   * @param cleartext
   *          Der FileInputStream, der den Klartext liefert.
   * @param ciphertext
   *          Der FileOutputStream, in den die Signatur geschrieben werden soll.
   */
  public void sign(FileInputStream cleartext, FileOutputStream ciphertext) {
    Random sc = new SecureRandom();

    int Lp = p.bitLength(); // bitlength of p (512 bit)
    int L = (Lp - 1) / 8; // blocksize

    // read cleartext
    BigInteger M = readClear(cleartext, L);
    while (M != null) {

      // random k with gcd(k, p-1) = 1
      BigInteger k = BigIntegerUtil.randomBetween(BigIntegerUtil.TWO, p.subtract(BigIntegerUtil.ONE), sc);
      while (!k.gcd(p.subtract(BigInteger.ONE)).equals(BigInteger.ONE)) {
        // random two <= k < p-1
        k = BigIntegerUtil.randomBetween(BigIntegerUtil.TWO, p.subtract(BigIntegerUtil.ONE), sc);
      }

      BigInteger r = g.modPow(k, p);

      BigInteger t = k.modInverse(p.subtract(BigInteger.ONE)); // t = k^-1 mod p-1

      BigInteger s = (M.subtract(x.multiply(r))).multiply(t); // (M-xr)k^-1
      s = s.mod(p.subtract(BigInteger.ONE)); // mod (p-1)

      BigInteger C = r.add(s.multiply(p)); // r + s*p

      writeCipher(ciphertext, C);

      M = readClear(cleartext, L);
    }
  }

  /**
   * Überprüft die durch den FileInputStream <code>ciphertext</code> gegebene Signatur auf den vom
   * FileInputStream <code>cleartext</code> gelieferten Klartext.
   * <p>
   * Das blockweise Lesen der Signatur soll mit der Methode {@link #readCipher readCipher}
   * durchgeführt werden, das blockweise Lesen des Klartextes mit der Methode {@link #readClear
   * readClear}.
   * </p>
   * 
   * @param ciphertext
   *          Der FileInputStream, der die zu prüfende Signatur liefert.
   * @param cleartext
   *          Der FileInputStream, der den Klartext liefert, auf den die Signatur überprüft werden
   *          soll.
   */
  public void verify(FileInputStream ciphertext, FileInputStream cleartext) {
    int Lp = p.bitLength(); // bitlength of p (512 bit)
    int L = (Lp - 1) / 8; // blocksize

    // read ciphertext
    BigInteger C = readCipher(ciphertext);
    BigInteger M = readClear(cleartext, L);

    Boolean verified = true;
    while (C != null && M != null) {
      BigInteger r = C.mod(p);
      BigInteger s = C.divide(p);

      if ((r.compareTo(BigInteger.ONE) >= 0) && (r.compareTo(p.subtract(BigInteger.ONE)) <= 0)) {
        BigInteger yr = y.modPow(r, p); // y^r mod p
        BigInteger rs = r.modPow(s, p); // r^s mod p

        BigInteger v1 = yr.multiply(rs).mod(p); // y^r * r^s mod p

        BigInteger v2 = g.modPow(M, p);

        if (!v1.equals(v2)) {
          verified = false;
        }
      } else {
        System.out.println("Abbruch, da r >= 1 oder r <= p-1 nicht erfüllt ist!");
        verified = false;
      }

      C = readCipher(ciphertext);
      M = readClear(cleartext, L);
    }

    if (verified) {
      System.out.println("Der Text wurde verifiziert!");
    } else {
      System.out.println("Der Text konnte nicht verifiziert werden!!!");
    }
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
    publicKeyFile = "bla.secr.public";
    privateKeyFile = "bla.secr.private";

    Writer writer = null;

    try {
      writer = new BufferedWriter(new FileWriter(publicKeyFile));
      writer.write(publicKey);
      writer.close();
    } catch (IOException e) {
      e.printStackTrace();
    }

    try {
      writer = new BufferedWriter(new FileWriter(privateKeyFile));
      writer.write(privateKey);
      writer.close();
    } catch (IOException e) {
      e.printStackTrace();
    }

    // write reference to files in key.txt
    try {
      key.write(publicKeyFile);
      key.newLine();
      key.write(privateKeyFile);

      Logger("Writing Information: ");
      Logger("+--publicKey: " + publicKey);
      Logger("+--privateKey: " + privateKey);

      key.close();
    } catch (IOException e) {
      System.out.println("Abbruch: Fehler beim Schreiben oder Schließen der " + "Schlüsseldatei.");
      e.printStackTrace();
      System.exit(1);
    }
  }

  private void Logger(String event) {
    System.out.println("ElGamal$  " + event);
  }
}
