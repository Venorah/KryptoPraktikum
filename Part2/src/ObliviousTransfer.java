import com.krypto.idea.IDEA;
import com.krypto.rsa.RSA;
import com.krypto.fingerprint.Fingerprint;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;
import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;
import de.tubs.cs.iti.krypto.protokoll.*;

public final class ObliviousTransfer implements Protocol {

  static private int MinPlayer = 2; // Minimal number of players
  static private int MaxPlayer = 2; // Maximal number of players
  static private String NameOfTheGame = "Station To Station";
  private Communicator Com;

  private BigInteger ONE = BigIntegerUtil.ONE;
  private BigInteger TWO = BigIntegerUtil.TWO;

  private boolean MitM = false;

  public void setCommunicator(Communicator com) {
    Com = com;
  }

  /**
   * Aktionen der beginnenden Partei. Bei den 2-Parteien-Protokollen seien dies die Aktionen von Alice.
   */
  public void sendFirst() {
    System.out.println("-- Alice --");
    if (MitM) {
      System.out.println("ACHTUNG: MitM aktiv!!!");
    }

  }

  /**
   * Aktionen der uebrigen Parteien. Bei den 2-Parteien-Protokollen seien dies die Aktionen von Bob.
   */
  public void receiveFirst() {
    System.out.println("-- Bob --");
    if (MitM) {
      System.out.println("ACHTUNG: MitM aktiv!!!");
    }

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