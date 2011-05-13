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
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.FileReader;
import java.math.BigInteger;
import java.util.Random;
import java.util.StringTokenizer;

import com.sun.org.apache.xml.internal.security.utils.HelperNodeList;

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
  public String cipherBlockChaining(String cipherPart, String messagePart) {
    String outputCipher = "";

    keys = getKeysAs2DArray("");

    BigInteger cp = Helper.stringToBigInteger(cipherPart);
    BigInteger mp = Helper.stringToBigInteger(messagePart);

    BigInteger input = cp.xor(mp);

    return outputCipher;
  }

  public String idea(String messagePart) {
    String cipher = "";

    // TODO idea stuff

    return cipher;
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

    BigInteger[] key = keys[round];
    BigInteger[] msg = Helper.extractValues(Helper.stringToBigInteger(messagePart), 16);

    BigInteger addMod = new BigInteger("65536"); // 2^16
    BigInteger multMod = new BigInteger("65537"); // (2^16)+1

    BigInteger M1 = msg[0];
    BigInteger M2 = msg[1];
    BigInteger M3 = msg[2];
    BigInteger M4 = msg[3];

    BigInteger K1 = key[0];
    BigInteger K2 = key[1];
    BigInteger K3 = key[2];
    BigInteger K4 = key[3];

    if (!isEnc) {
      K1 = (key[0]).modInverse(multMod);
      K2 = (key[1]).modInverse(multMod);
      K3 = ((key[2]).negate()).mod(addMod);
      K4 = ((key[3]).negate()).mod(addMod);

    }

    if (round != 8) {

      BigInteger K5 = key[4];
      BigInteger K6 = key[5];

      BigInteger calc01 = new BigInteger("0");
      BigInteger calc02 = new BigInteger("0");
      BigInteger calc03 = new BigInteger("0");
      BigInteger calc04 = new BigInteger("0");
      BigInteger calc05 = new BigInteger("0");
      BigInteger calc06 = new BigInteger("0");
      BigInteger calc07 = new BigInteger("0");
      BigInteger calc08 = new BigInteger("0");
      BigInteger calc09 = new BigInteger("0");
      BigInteger calc10 = new BigInteger("0");
      BigInteger calc11 = new BigInteger("0");
      BigInteger calc12 = new BigInteger("0");
      BigInteger calc13 = new BigInteger("0");
      BigInteger calc14 = new BigInteger("0");

      calc01 = (K1.multiply(M1)).mod(multMod);
      calc02 = (K2.multiply(M2)).mod(multMod);
      calc03 = (K3.add(M3)).mod(addMod);
      calc04 = (K4.add(M4)).mod(addMod);
      calc05 = calc01.xor(calc03);
      calc06 = calc02.xor(calc04);
      calc07 = (K5.multiply(calc05)).mod(multMod);
      calc08 = (calc07.add(calc06)).mod(addMod);
      calc09 = (K6.multiply(calc08)).mod(multMod);
      calc10 = (calc09.add(calc07)).mod(addMod);
      calc11 = calc09.xor(calc01);
      calc12 = calc09.xor(calc03);
      calc13 = calc10.xor(calc02);
      calc14 = calc10.xor(calc04);

      BigInteger[] c1 = Helper.extractValues(calc12, 8);
      BigInteger[] c2 = Helper.extractValues(calc14, 8);
      BigInteger[] c3 = Helper.extractValues(calc11, 8);
      BigInteger[] c4 = Helper.extractValues(calc13, 8);

      BigInteger[] result = { c1[0], c1[1], c2[0], c2[1], c3[0], c3[1], c4[0], c4[1] };
      // BigInteger[] result = { calc12, calc14, calc11, calc13 };

      output = Helper.bigIntegerArrayToString(result);

    } else {

      BigInteger calc01 = new BigInteger("0");
      BigInteger calc02 = new BigInteger("0");
      BigInteger calc03 = new BigInteger("0");
      BigInteger calc04 = new BigInteger("0");

      calc01 = (K1.multiply(M1)).mod(multMod);
      calc02 = (K2.multiply(M2)).mod(multMod);
      calc03 = (K3.add(M3)).mod(addMod);
      calc04 = (K4.add(M4)).mod(addMod);

      BigInteger[] c1 = Helper.extractValues(calc01, 8);
      BigInteger[] c2 = Helper.extractValues(calc02, 8);
      BigInteger[] c3 = Helper.extractValues(calc03, 8);
      BigInteger[] c4 = Helper.extractValues(calc04, 8);

      BigInteger[] result = { c1[0], c1[1], c2[0], c2[1], c3[0], c3[1], c4[0], c4[1] };

      // BigInteger[] result = { calc01, calc02, calc03, calc04 };
      output = Helper.bigIntegerArrayToString(result);
    }

    return output;
  }

  public BigInteger[] getSubBlocks(String textPart) {
    BigInteger[] array = new BigInteger[(textPart.length()) / 2];

    BigInteger[] bigArray = Helper.stringToBigIntegerArray(textPart);

    for (int i = 0, j = 0; i < bigArray.length; i = i + 2, j++) {
      BigInteger val1 = bigArray[i];
      BigInteger val2 = bigArray[i + 1];

      array[j] = Helper.byteToShort(val1, val2);
    }

    return array;
  }

  public BigInteger[] getKeys(String keyString) {
    BigInteger[] outputArray = new BigInteger[52];

    String key = new String(keyString);
    BigInteger[] byteKeyArray = Helper.stringToBigIntegerArray(key);
    BigInteger[] shortKeyArray = Helper.byteArrayToShortArray(byteKeyArray);

    int i = 0;
    while (i != 52) {
      for (int j = 0; j < shortKeyArray.length; j++) {
        outputArray[i++] = shortKeyArray[j];
        if (i == 52) {
          break;
        }
      }
      if (i != 52) {
        key = cyclicShift(key, 25, true);
        byteKeyArray = Helper.stringToBigIntegerArray(key);
        shortKeyArray = Helper.byteArrayToShortArray(byteKeyArray);
      }
    }

    return outputArray;
  }

  public BigInteger[][] getKeysAs2DArray(String keyString) {

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

    return nicerArray;
  }

  public String cyclicShift(String text, int positions, boolean isLeftShift) {

    String outputString = "";

    BigInteger[] array = Helper.stringToBigIntegerArray(text);
    String binaryString = "";

    for (int i = 0; i < array.length; i++) {
      String currentString = Helper.decimalToBinaryString(array[i].intValue());

      if (currentString.length() != 8) {
        currentString = Helper.prependZeros(currentString, 8);
      }

      binaryString += currentString;
    }

    char[] binaryStringArray = binaryString.toCharArray();
    char[] shiftedArray = new char[binaryStringArray.length];
    int length = binaryStringArray.length;

    if (isLeftShift) {
      for (int i = 0; i < length; i++) {
        int field = ((i - positions) + length * 2) % length;
        shiftedArray[field] = binaryStringArray[i];
      }
    } else {
      for (int i = 0; i < length; i++) {
        int field = ((i + positions) + length * 2) % length;
        shiftedArray[field] = binaryStringArray[i];
      }
    }

    String shiftedBinaryString = String.valueOf(shiftedArray);
    String[] shiftedBinaryStringArray = Helper.getTextAsStringArray(shiftedBinaryString, 8);

    for (int i = 0; i < shiftedBinaryStringArray.length; i++) {
      char character = (char) Helper.binaryStringToDecimal(shiftedBinaryStringArray[i]);
      outputString += character;
    }

    return outputString;
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
