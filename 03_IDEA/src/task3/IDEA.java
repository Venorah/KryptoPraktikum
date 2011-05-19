/*
 * jCrypt - Programmierumgebung für das Kryptologie-Praktikum
 * Studienarbeit am Institut für Theoretische Informatik der
 * Technischen Universität Braunschweig
 * 
 * Datei:        IDEA.java
 * Beschreibung: Dummy-Implementierung des International Data Encryption
 *               Algorithm (IDEA)
 * Erstellt:     30. März 2010
 * Autor:        Martin Klußmann
 */

package task3;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;
import de.tubs.cs.iti.jcrypt.chiffre.BlockCipher;

/**
 * Dummy-Klasse für den International Data Encryption Algorithm (IDEA).
 * 
 * @author Martin Klußmann
 * @version 1.1 - Sat Apr 03 21:57:35 CEST 2010
 */
public final class IDEA extends BlockCipher {

  String keyString;
  static BigInteger[][] keys;

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

      String keyString = new String(key.readLine());

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

  /**
   * Schreibt den Schlüssel mit dem Writer <code>key</code>.
   * 
   * @param key
   *          Der Writer, der in die Schlüsseldatei schreibt.
   * @see #makeKey makeKey
   * @see #readKey readKey
   */
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

    String clearTextString = Helper.getTextAsString(cleartext);
    String[] clearTextArray = Helper.getTextAsStringArray(clearTextString, 8);

  }

  public void decipher(FileInputStream ciphertext, FileOutputStream cleartext) {
    // TODO
  }

  /**
   * @param cipherPart
   *          64 bit
   * @param messagePart
   *          64 bit
   * @return Ciphertext part
   */
  public static String cipherBlockChaining(String message, boolean isEncryption) {
    String outputCipher = "";

    // keys = getKeysAs2DArray("");

    String[] messageParts = Helper.getTextAsStringArray(message, 8);
    String cipherPart = "ÝÃ¨öÆbÒ";

    for (int i = 0; i < messageParts.length; i++) {

      String messagePart = messageParts[i];

      BigInteger mp = Helper.stringToBigInteger(messagePart);
      BigInteger cp = Helper.stringToBigInteger(cipherPart);
      BigInteger result = cp.xor(mp);

      BigInteger[] resultArray = Helper.extractValues(result, 8, 8);
      String ideaInput = Helper.bigIntegerArrayToString(resultArray);

      cipherPart = idea(ideaInput, isEncryption);

      outputCipher += cipherPart;

    }

    return outputCipher;
  }

  public static String idea(String messagePart, boolean isEncryption) {

    String cipherPart = messagePart;

    for (int round = 0; round < 9; round++) {
      cipherPart = feistelNetwork(cipherPart, round, isEncryption);
    }

    return cipherPart;
  }

  /**
   * 
   * @param messagePart
   * @param round
   *          0-8 = 9 Rounds possible
   * @param isEnc
   *          switch for enc/dec
   * @return
   */
  public static String feistelNetwork(String messagePart, int round, boolean isEnc) {
    String output = "";

    // BigInteger[] key = keys[round];

    BigInteger[][] encKeys = getKeysAs2DArray("abcdefghijklmnop");

    BigInteger[] key;
    if (isEnc) {
      key = encKeys[round];
    } else {
      BigInteger[][] decKeys = getDecryptionKeys(encKeys);
      key = decKeys[round];
    }

    BigInteger[] msg = Helper.extractValues(Helper.stringToBigInteger(messagePart), 16, 4);

    BigInteger addMod = new BigInteger("65536"); // 2^16
    BigInteger multMod = new BigInteger("65537"); // (2^16)+1

    BigInteger[] M = new BigInteger[5];
    M[1] = msg[0];
    M[2] = msg[1];
    M[3] = msg[2];
    M[4] = msg[3];

    BigInteger[] K = new BigInteger[7];
    K[1] = key[0];
    K[2] = key[1];
    K[3] = key[2];
    K[4] = key[3];

    if (round < 8) {

      K[5] = key[4];
      K[6] = key[5];

      BigInteger[] calc = new BigInteger[15];

      calc[1] = (K[1].multiply(M[1])).mod(multMod);
      calc[2] = (K[2].multiply(M[2])).mod(multMod);
      calc[3] = (K[3].add(M[3])).mod(addMod);
      calc[4] = (K[4].add(M[4])).mod(addMod);
      calc[5] = calc[1].xor(calc[3]);
      calc[6] = calc[2].xor(calc[4]);
      calc[7] = (K[5].multiply(calc[5])).mod(multMod);
      calc[8] = (calc[7].add(calc[6])).mod(addMod);
      calc[9] = (K[6].multiply(calc[8])).mod(multMod);
      calc[10] = (calc[9].add(calc[7])).mod(addMod);
      calc[11] = calc[9].xor(calc[1]);
      calc[12] = calc[9].xor(calc[3]);
      calc[13] = calc[10].xor(calc[2]);
      calc[14] = calc[10].xor(calc[4]);

      System.out.println("R" + round + ": " + calc[12].toString(16) + " " + calc[14].toString(16) + " " + calc[11].toString(16) + " " + calc[13].toString(16));

      BigInteger[] c1 = Helper.extractValues(calc[12], 8, 2);
      BigInteger[] c2 = Helper.extractValues(calc[14], 8, 2);
      BigInteger[] c3 = Helper.extractValues(calc[11], 8, 2);
      BigInteger[] c4 = Helper.extractValues(calc[13], 8, 2);

      BigInteger[] result = { c1[0], c1[1], c2[0], c2[1], c3[0], c3[1], c4[0], c4[1] };
      // BigInteger[] result = { calc12, calc14, calc11, calc13 };

      output = Helper.bigIntegerArrayToString(result);

    } else {

      BigInteger[] calc = new BigInteger[5];

      calc[1] = (K[1].multiply(M[1])).mod(multMod);
      calc[2] = (K[2].multiply(M[2])).mod(multMod);
      calc[3] = (K[3].add(M[3])).mod(addMod);
      calc[4] = (K[4].add(M[4])).mod(addMod);

      System.out.println("R" + round + ": " + calc[1].toString(16) + " " + calc[2].toString(16) + " " + calc[3].toString(16) + " " + calc[4].toString(16));

      BigInteger[] c1 = Helper.extractValues(calc[1], 8, 2);
      BigInteger[] c2 = Helper.extractValues(calc[2], 8, 2);
      BigInteger[] c3 = Helper.extractValues(calc[3], 8, 2);
      BigInteger[] c4 = Helper.extractValues(calc[4], 8, 2);

      BigInteger[] result = { c1[0], c1[1], c2[0], c2[1], c3[0], c3[1], c4[0], c4[1] };

      // BigInteger[] result = { calc01, calc02, calc03, calc04 };
      output = Helper.bigIntegerArrayToString(result);
    }

    return output;
  }

  public static BigInteger[] getSubBlocks(String textPart) {
    BigInteger[] array = new BigInteger[(textPart.length()) / 2];

    BigInteger[] bigArray = Helper.stringToBigIntegerArray(textPart);

    for (int i = 0, j = 0; i < bigArray.length; i = i + 2, j++) {
      BigInteger val1 = bigArray[i];
      BigInteger val2 = bigArray[i + 1];

      array[j] = Helper.byteToShort(val1, val2);
    }

    return array;
  }

  public static BigInteger[] getKeys(String keyString) {
    BigInteger[] outputArray = new BigInteger[52];

    BigInteger[] keyArray = Helper.stringToBigIntegerArray(keyString);
    BigInteger key = Helper.bigIntegerArraySum(keyArray);

    BigInteger[] shortKeyArray = Helper.extractValues(key, 16, 8);

    int i = 0;
    while (i != 52) {

      for (int j = 0; j < shortKeyArray.length; j++) {
        BigInteger tmp = shortKeyArray[j];
        outputArray[i++] = tmp;
        if (i == 52) {
          break;
        }
      }

      if (i != 52) {
        key = Helper.shift(key, 16, 25);
        shortKeyArray = Helper.extractValues(key, 16, 8);
      }
    }

    return outputArray;
  }

  public static BigInteger[][] getKeysAs2DArray(String keyString) {

    BigInteger[] uglyArray = getKeys(keyString);
    BigInteger[][] nicerArray = new BigInteger[9][6];

    int counter = 0;
    for (int zeile = 0; zeile < nicerArray.length; zeile++) {
      for (int spalte = 0; spalte < nicerArray[zeile].length; spalte++) {
        nicerArray[zeile][spalte] = uglyArray[counter++];
        if (counter == 52) {
          return nicerArray;
        }
      }
    }

    System.out.println();
    return nicerArray;
  }

  public static BigInteger[][] getDecryptionKeys(BigInteger[][] encryptionKeys) {
    BigInteger[][] dencryptionKeys = new BigInteger[9][6];

    // reverse array
    for (int column = 0; column < 9; column++) {
      if (column == 0) {
        dencryptionKeys[column][0] = encryptionKeys[8 - column][0];
        dencryptionKeys[column][1] = encryptionKeys[8 - column][1];
        dencryptionKeys[column][2] = encryptionKeys[8 - column][2];
        dencryptionKeys[column][3] = encryptionKeys[8 - column][3];
        dencryptionKeys[column][4] = encryptionKeys[7 - column][4];
        dencryptionKeys[column][5] = encryptionKeys[7 - column][5];
      } else if (column > 0 && column < 8) {
        dencryptionKeys[column][0] = encryptionKeys[8 - column][0];
        dencryptionKeys[column][1] = encryptionKeys[8 - column][2];
        dencryptionKeys[column][2] = encryptionKeys[8 - column][1];
        dencryptionKeys[column][3] = encryptionKeys[8 - column][3];
        dencryptionKeys[column][4] = encryptionKeys[7 - column][4];
        dencryptionKeys[column][5] = encryptionKeys[7 - column][5];
      } else {
        dencryptionKeys[column][0] = encryptionKeys[8 - column][0];
        dencryptionKeys[column][1] = encryptionKeys[8 - column][1];
        dencryptionKeys[column][2] = encryptionKeys[8 - column][2];
        dencryptionKeys[column][3] = encryptionKeys[8 - column][3];
        dencryptionKeys[column][4] = null;
        dencryptionKeys[column][5] = null;
      }
    }
    
    BigInteger addMod = new BigInteger("65536"); // 2^16
    BigInteger multMod = new BigInteger("65537"); // (2^16)+1
    
    // calculate multiplicative inverse and negate mod
    for (int column = 0; column < dencryptionKeys.length; column++) {
      for (int row = 0; row < dencryptionKeys[column].length; row++) {
        if (row == 0 || row == 3) {
          BigInteger val = dencryptionKeys[column][row];
          val = val.modInverse(multMod);
          dencryptionKeys[column][row] = val;
        } else if (row == 1 || row == 2) {
          BigInteger val = dencryptionKeys[column][row];
          val = val.negate();
          val = val.mod(addMod);
          dencryptionKeys[column][row] = val;
        } else {
          dencryptionKeys[column][row] = dencryptionKeys[column][row];
        }
      }
    }

    return dencryptionKeys;
  }

  /**
   * Erzeugt einen neuen Schlüssel.
   * 
   * @see #readKey readKey
   * @see #writeKey writeKey
   */
  public void makeKey() {
    BufferedReader standardInput = launcher.openStandardInput();
    keyString = new String();
    char keyCharArray[] = new char[16];

    // Auswahl eingeben oder generieren:
    int choice = -1;
    try {
      Logger("[0] Möchtest du einen eigenen Schlüssel eingeben\n[1] oder einen Schlüssel zufällig generieren?");
      choice = Integer.parseInt(standardInput.readLine());
    } catch (NumberFormatException e) {
      e.printStackTrace();
    } catch (IOException e) {
      Logger("Problem beim Einlesen");
      e.printStackTrace();
    }

    if (choice == 0) { // eingeben

      try {
        Logger("Bitte gib einen 16 Zeichen langen Schlüssel ein:");
        keyString = standardInput.readLine();
      } catch (NumberFormatException e) {
        e.printStackTrace();
      } catch (IOException e) {
        Logger("Problem beim Einlesen");
        e.printStackTrace();
      }

      if (keyString.length() == 16) {
        keyCharArray = keyString.toCharArray();
        for (int i = 0; i < keyCharArray.length; i++) {
          if (keyCharArray[i] > 128) { // > 2^8-1
            Logger("Du hast ein Sonderzeichen verwendet, das nicht im ASCII-Zeichensatz verfügbar ist.");
            System.exit(0);
          }
        }
      } else {
        Logger("Der Schlüssel muss 16 Zeichen lang sein!");
      }

    } else if (choice == 1) { // zufällig generieren
      Random rand = new Random();

      for (int i = 0; i < keyCharArray.length; i++) {
        keyCharArray[i] = (char) rand.nextInt(128); // zufällig von 0...127
        keyString += "" + keyCharArray[i];
      }

      // print info
      String integerValues = new String();
      for (int i = 0; i < keyCharArray.length; i++) {
        integerValues += "" + (int) keyCharArray[i] + ", ";
      }

      Logger("Zufällige Werte: " + integerValues);
      Logger("Der Schlüssel wurde zufällig generiert!");
    } else {
      Logger("Falsche Eingabe!");
    }

  }

  private static void Logger(String event) {
    System.out.println("IDEA$  " + event);
  }
}
