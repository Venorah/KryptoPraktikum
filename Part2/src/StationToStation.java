import com.krypto.idea.IDEA;

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

  BigInteger p, g; // Primzahl p, prim. W. g

  BigInteger e_A, n_A, d_A; // Alice Werte

  BigInteger e_B, n_B, d_B; // Bob Werte

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
      p = q.multiply(BigIntegerUtil.TWO).add(BigIntegerUtil.ONE); // secure
      // prime
      // p =
      // 2q+1
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

  public void generateRSAKeys() {
    Random sc = new SecureRandom();
    int k = 512; // prime number with k=512 bits
    int certainty = 100; // The probability that the new BigInteger
    // represents a prime number will
    // exceed (1-1/2^certainty)

    BigInteger p = new BigInteger(k - 1, certainty, sc);
    BigInteger q = new BigInteger(k - 1, certainty, sc);

    // n=pq
    BigInteger n = p.multiply(q);

    // phi(n) = (p-1)(q-1)
    BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
    
    
  }

  public void setCommunicator(Communicator com) {
    Com = com;
  }

  /**
   * Aktionen der beginnenden Partei. Bei den 2-Parteien-Protokollen seien dies die Aktionen von Alice.
   */
  public void sendFirst() {
    System.out.println("alice test");

    // IDEA idea = new IDEA();

    // (0)
    // todo: fingerprint werte aus datei auslesen

    // alice wählt p und g und sendet diese an bob
    getPrimeAndGenerator();
    System.out.println("p: " + p);
    System.out.println("g: " + g);
    Com.sendTo(1, p.toString(16));
    Com.sendTo(1, g.toString(16));

    // alice sendet öffentlichen schlüssel (e_A, n_A) an bob

  }

  /**
   * Aktionen der uebrigen Parteien. Bei den 2-Parteien-Protokollen seien dies die Aktionen von Bob.
   */
  public void receiveFirst() {
    // bob bekommt öffentlichen schlüssel von alice
    p = new BigInteger(Com.receive(), 16);
    g = new BigInteger(Com.receive(), 16);
    System.out.println("p: " + p);
    System.out.println("g: " + g);

    // bob sendet seinen öffentlichen schlüssel (e_B, n_B)
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
