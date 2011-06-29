import com.krypto.elGamal.ElGamal;

import java.math.BigInteger;
import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;
import de.tubs.cs.iti.krypto.protokoll.*;

public final class Geheimnis implements Protocol {

  static private int MinPlayer = 2; // Minimal number of players
  static private int MaxPlayer = 2; // Maximal number of players
  static private String NameOfTheGame = "Geheimnisaustausch";
  private Communicator Com;

  private BigInteger ZERO = BigIntegerUtil.ZERO;
  private BigInteger ONE = BigIntegerUtil.ONE;
  private BigInteger TWO = BigIntegerUtil.TWO;

  private boolean betray = false;

  public void setCommunicator(Communicator com) {
    Com = com;
  }

  /**
   * Aktionen der beginnenden Partei. Bei den 2-Parteien-Protokollen seien dies die Aktionen von Alice.
   */
  public void sendFirst() {
    System.out.println("-- Alice --");
    if (betray) {
      System.out.println("ACHTUNG: Betrugsmodus aktiv!!!");
    }

    
  }

  /**
   * Aktionen der uebrigen Parteien. Bei den 2-Parteien-Protokollen seien dies die Aktionen von Bob.
   */
  public void receiveFirst() {
    System.out.println("-- Bob --");
    if (betray) {
      System.out.println("ACHTUNG: Betrugsmodus aktiv!!!");
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