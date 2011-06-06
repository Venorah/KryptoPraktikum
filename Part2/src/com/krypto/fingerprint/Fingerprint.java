/*
 * jCrypt - Programmierumgebung für das Kryptologie-Praktikum
 * Studienarbeit am Institut für Theoretische Informatik der
 * Technischen Universität Braunschweig
 * 
 * Datei:        Fingerprint.java
 * Beschreibung: Dummy-Implementierung der Hash-Funktion von Chaum, van Heijst
 *               und Pfitzmann
 * Erstellt:     30. März 2010
 * Autor:        Martin Klußmann
 */

package com.krypto.fingerprint;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;
import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;

/**
 * Dummy-Klasse für die Hash-Funktion von Chaum, van Heijst und Pfitzmann.
 * 
 * @author Martin Klußmann
 * @version 1.1 - Sat Apr 03 22:20:18 CEST 2010
 */
public final class Fingerprint {

  private BigInteger ZERO = BigInteger.ZERO;
  private BigInteger ONE = BigInteger.ONE;
  private BigInteger TWO = BigIntegerUtil.TWO;

  private BigInteger p;
  private BigInteger g1;
  private BigInteger g2;
  private String paramString;
  private int Lp = 512;
  private int Lq = 511;

  public Fingerprint(File file) {
    try {
      BufferedReader in = new BufferedReader(new FileReader(file));
      readParam(in);
    } catch (FileNotFoundException e) {
      e.printStackTrace();
    }
  }

  /**
   * Erzeugt neue Parameter.
   * 
   * @see #readParam readParam
   * @see #writeParam writeParam
   */
  public static void makeParam() {
    BigInteger ZERO = BigInteger.ZERO;
    BigInteger ONE = BigInteger.ONE;
    BigInteger TWO = BigIntegerUtil.TWO;

    int Lp = 512;
    int Lq = 511;

    Random sc = new SecureRandom();
    int k = Lp; // prime number with k=512 bits
    int certainty = 100; // The probability that the new BigInteger represents a prime number will
                         // exceed (1-1/2^certainty)

    BigInteger p = null;
    BigInteger q = null;
    do {
      q = new BigInteger(k - 1, certainty, sc);
      p = q.multiply(TWO).add(ONE); // secure prime p = 2q+1
    } while (!p.isProbablePrime(certainty));

    BigInteger MINUS_ONE = ONE.negate().mod(p); // -1 mod p

    BigInteger g1 = null;
    BigInteger factor = null;
    do {
      // 2 <= g < p-1
      g1 = BigIntegerUtil.randomBetween(TWO, p.subtract(ONE), sc);
      factor = g1.modPow(q, p);
    } while (!factor.equals(MINUS_ONE));

    BigInteger g2 = null;
    BigInteger factor2 = null;
    do {
      do {
        // 2 <= g < p-1
        g2 = BigIntegerUtil.randomBetween(TWO, p.subtract(ONE), sc);
        factor2 = g2.modPow(q, p);
      } while (!factor2.equals(MINUS_ONE));
    } while (g1.equals(g2));

    String paramString = p + "\n" + g1 + "\n" + g2;

    try {
      BufferedWriter param = new BufferedWriter(new FileWriter("HashParameter"));
      param.write(paramString);
      param.close();
    } catch (IOException e1) {
      e1.printStackTrace();
    }

  }

  /**
   * Liest die Parameter mit dem Reader <code>param</code>.
   * 
   * @param param
   *          Der Reader, der aus der Parameterdatei liest.
   * @see #makeParam makeParam
   * @see #writeParam writeParam
   */
  public void readParam(BufferedReader param) {
    try {
      // pubkey
      p = new BigInteger(param.readLine());
      g1 = new BigInteger(param.readLine());
      g2 = new BigInteger(param.readLine());

      paramString = p + "\n" + g1 + "\n" + g2;
    } catch (FileNotFoundException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  public BigInteger hash(String cleartext) {
    String messageString = cleartext;
    BigInteger message = new BigInteger(messageString.getBytes());

    Logger("message.bitLength()=" + message.bitLength());
    Logger("Lp=" + Lp + "  " + " Lq=" + Lq);

    BigInteger hash = computeHash(message);
    Logger("Hash: " + hash);

    // String output = hash.toString(16);
    return hash;

  }

  public boolean verify(BigInteger hash, String cleartext) {

    // BigInteger hash = new BigInteger(hashAsHEX, 16);

    String messageString = cleartext;
    BigInteger message = new BigInteger(messageString.getBytes());

    Logger("hash.bitLength()=" + hash.bitLength());
    Logger("message.bitLength()=" + message.bitLength());
    Logger("Lp=" + Lp + "  " + " Lq=" + Lq);

    BigInteger hash2 = computeHash(message);

    Logger("Hash1: " + hash.toString(16));
    Logger("Hash2: " + hash2.toString(16));

    if (hash.compareTo(hash2) == 0) {
      Logger("Message verified");
      return true;
    } else {
      Logger("Message verification failed");
      return false;
    }

  }

  /**
   * 
   * @param message
   * @return
   */
  private BigInteger computeHash(BigInteger message) {
    int m = 2 * (Lq - 1);
    int t = Lp;
    int n = message.bitLength();
    int k = (int) (Math.ceil((double) n / (double) (m - t - 1)));
    int Lx = m - t - 1;
    Logger("m=" + m + " t=" + t + " n=" + n + " k=" + k + " Lx=" + Lx);

    BigInteger[] x = splitMessage(message, Lx, k);
    Logger("x :" + ArrayLogger(x));

    /* Part (1) of Algorithm 6.1 */
    BigInteger[] y = new BigInteger[k + 1]; // y+1 wird noch gebraucht
    for (int i = 0; i <= k - 1; i++) {
      y[i] = x[i];
    }
    Logger("y0:" + ArrayLogger(y));

    /* Part (2) of Algorithm 6.1 */
    int Lxk = x[k - 1].bitLength();
    int d = Lx - Lxk;
    Logger("Lx=" + Lx + " Lxk=" + Lxk + " d=" + d);
    BigInteger yk_minus1 = y[k - 1];
    y[k - 1] = x[k - 1].shiftLeft(d);
    Logger("BEFORE: y[k-1].bitLength()=" + yk_minus1.bitLength() + " =.= AFTER: y[k-1].bitLength()=" + y[k - 1].bitLength());
    Logger("y1:" + ArrayLogger(y));

    /* Part (3) of Algorithm 6.1 */
    y[k] = new BigInteger(d + ""); // y[k+1] ausm Buch
    Logger("y2:" + ArrayLogger(y));

    /* Part (4) of Algorithm 6.1 */
    BigInteger g = ZERO; // Kein Array, soll rekursiv sein
    g = h(y[0], Lx);

    /* Part (5) of Algorithm 6.1 */
    for (int i = 0; i <= k - 1; i++) {
      g = (g.shiftLeft(1)).add(ONE);
      g = (g.shiftLeft(y[i + 1].bitLength())).add(y[i + 1]);
      g = h(g, Lx);
    }

    return g;
  }

  /**
   * 
   * @param message
   * @param k
   * @return
   */
  private BigInteger h(BigInteger message, int k) {

    BigInteger x1 = message.shiftRight(k);
    BigInteger x2 = message.xor(x1.shiftLeft(k));

    BigInteger g1x1 = g1.modPow(x1, p);
    BigInteger g2x2 = g2.modPow(x2, p);

    BigInteger hash = (g1x1.multiply(g2x2)).mod(p);
    return hash;
  }

  /**
   * 
   * @param message
   * @param blockLength
   * @param k
   * @return
   */
  private BigInteger[] splitMessage(BigInteger message, int blockLength, int k) {
    BigInteger[] output = new BigInteger[k];

    int counter = k - 1;
    while (message.bitLength() > blockLength) {

      // 101 11001100.shiftRight(8) = 101
      // 101.shiftLeft(8) = 101 000000000
      // 101 11001100.xor(101 000000000) = 000 11001100
      BigInteger removedLowestBits = (message.shiftRight(blockLength)).shiftLeft(blockLength);
      output[counter--] = message.xor(removedLowestBits);

      message = message.shiftRight(blockLength);
    }

    if (message.bitLength() != 0) {
      output[counter] = message;
    }

    return output;
  }

  /**
   * 
   * @param event
   */
  private void Logger(String event) {
    // System.out.println("#$  " + event);
  }

  /**
   * 
   * @param array
   * @return
   */
  private String ArrayLogger(BigInteger[] array) {
    String output = "";
    for (int i = 0; i < array.length; i++) {
      BigInteger currentValue = array[i];

      if (currentValue == null) {
        output += "[" + i + "]" + "----  ";
      } else {
        output += "[" + i + "]" + currentValue + "  ";
      }
    }

    return output;
  }

}
