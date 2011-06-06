import com.krypto.idea.IDEA;
import com.krypto.rsa.RSA;
import com.krypto.fingerprint.Fingerprint;

import java.io.File;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;
import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;
import de.tubs.cs.iti.krypto.protokoll.*;

public final class StationToStation implements Protocol {

  static private int MinPlayer = 2; // Minimal number of players
  static private int MaxPlayer = 2; // Maximal number of players
  static private String NameOfTheGame = "Station To Station";
  private Communicator Com;

  BigInteger ZERO = BigIntegerUtil.ZERO;
  BigInteger ONE = BigIntegerUtil.ONE;
  BigInteger TWO = BigIntegerUtil.TWO;

  BigInteger p, g; // Primzahl p, prim. W. g

  BigInteger x, y, S;
  BigInteger x_remote, y_remote, S_remote;

  public void getPrimeAndGenerator() {
    Random sc = new SecureRandom();
    int k = 512; // prime number with k=512 bits
    int certainty = 100; // The probability that the new BigInteger
    // represents a prime number will
    // exceed (1-1/2^certainty)

    p = null;
    BigInteger q = null;
    do {
      q = new BigInteger(k - 1, certainty, sc);
      p = q.multiply(TWO).add(ONE); // secure
      // prime
      // p =
      // 2q+1
    } while (!p.isProbablePrime(certainty));

    BigInteger MINUS_ONE = ONE.negate().mod(p); // -1 mod p

    g = null;
    BigInteger factor = null;
    do {
      // 2  randomBetween 1  randomBetween 1 <= x_B < p-1
    BigInteger x_B = BigIntegerUtil.randomBetween(ONE, p.subtract(ONE));
    // bob wählt x_B = g^(x_B) mod p
    BigInteger y_B = g.modPow(x_B, p);
    // y_B an alice senden
    Com.sendTo(0, y_B.toString(16));

    // bob bestimmt schlüssel
    BigInteger k = y_A.modPow(x_B, p);
    System.out.println("k: "+k.toString());

    // signatur
    BigInteger m = y_B.multiply(p).add(y_A); // h(y_B,y_A) = y_B  p + y_A laut heft
    BigInteger hash = fingerprint.hash(m.toString(16));
    BigInteger S_B = rsa_B.getSignatur(hash); // S_B = hash^d_B mod n_B
    System.out.println("Signatur S_B: " + S_B);
    
    // zertifikat
    TrustedAuthority ta = new TrustedAuthority();
    String id = "Bob";
    byte[] data = id.getBytes();
    Certificate Z_B = ta.newCertificate(data);
    
    // bob sendet 
    Com.sendTo(0, Z_B.toString());
    Com.sendTo(0, y_B.toString(16));
    
    // enctypted with idea
    int l = k.bitLength();
    BigInteger key = k.shiftRight(l-128);
    System.out.println(key);
    System.out.println(key.bitLength());
    IDEA idea = new IDEA(key);
    
//    Com.sendTo(0, .toString());

  }

  public String nameOfTheGame() {
    return NameOfTheGame;
  }

  public int minPlayer() {
    return MinPlayer;
  }

  public int maxPlayer() {
    return MaxPlayer;
  }
}
