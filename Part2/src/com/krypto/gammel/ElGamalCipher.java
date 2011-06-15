package com.krypto.gammel;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;
import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;

public final class ElGamalCipher {
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

  public ElGamalCipher(BigInteger p, BigInteger g, BigInteger y, BigInteger x) {
    this.p = p;
    this.g = g;
    this.y = y;
    this.x = x;
  }
  
  public ElGamalCipher(BigInteger p, BigInteger g, BigInteger y) {
    this.p = p;
    this.g = g;
    this.y = y;
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

  public BigInteger encipher(BigInteger message) {
    Random sc = new SecureRandom();

    int Lp = p.bitLength(); // bitlength of p (512 bit)
    int L = (Lp - 1) / 8; // blocksize

    // read cleartext
    BigInteger M = message;
    // random two <= k < p-1
    BigInteger k = BigIntegerUtil.randomBetween(BigIntegerUtil.TWO, p.subtract(BigIntegerUtil.ONE), sc);

    BigInteger a = g.modPow(k, p); // g^k mod p
    BigInteger b = M.multiply(y.modPow(k, p)).mod(p); // (M * y^k mod p) mod p

    BigInteger C = a.add(b.multiply(p)); // a + b*p

    return C;

  }

  public BigInteger decipher(BigInteger cipher) {
    // read ciphertext
    BigInteger C = cipher;
    BigInteger a = C.mod(p);
    BigInteger b = C.divide(p);

    BigInteger exponent = p.subtract(BigInteger.ONE).subtract(x);
    BigInteger z = a.modPow(exponent, p); // a^(p-1-x) mod p

    BigInteger M = z.multiply(b).mod(p); // M = z * b mod p

    return M;
  }

  private void Logger(String event) {
    System.out.println("ElGamal$  " + event);
  }

}
