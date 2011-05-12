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

import de.tubs.cs.iti.jcrypt.chiffre.BlockCipher;

/**
 * Dummy-Klasse für den International Data Encryption Algorithm (IDEA).
 * 
 * @author Martin Klußmann
 * @version 1.1 - Sat Apr 03 21:57:35 CEST 2010
 */
public final class IDEA extends BlockCipher {

  String keyString;

  /**
   * Entschlüsselt den durch den FileInputStream <code>ciphertext</code> gegebenen Chiffretext und
   * schreibt den Klartext in den FileOutputStream <code>cleartext</code>.
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
   * 
   * @param cleartext
   *          Der FileInputStream, der den Klartext liefert.
   * @param ciphertext
   *          Der FileOutputStream, in den der Chiffretext geschrieben werden soll.
   */
  public void encipher(FileInputStream cleartext, FileOutputStream ciphertext) {

    String clearTextString = getTextAsString(cleartext);
    String[] clearTextArray = getTextAsStringArray(clearTextString, 8);

  }

  private String getTextAsString(FileInputStream cleartext) {
    StringBuffer clearTextBuffer = new StringBuffer();

    try {
      int ch = 0;
      while ((ch = cleartext.read()) != -1) {
        clearTextBuffer.append((char) ch);
      }
    } catch (IOException e) {
      e.printStackTrace();
    }

    return clearTextBuffer.toString();
  }

  public BigInteger[] getSubBlocks(String textPart) {
    BigInteger[] array = new BigInteger[(textPart.length()) / 2];

    BigInteger[] bigArray = stringToBigIntegerArray(textPart);

    for (int i = 0, j = 0; i < bigArray.length; i = i + 2, j++) {
      BigInteger val1 = bigArray[i];
      BigInteger val2 = bigArray[i + 1];

      array[j] = byteToShort(val1, val2);
    }

    return array;
  }

  public String cyclicShift(String text, int positions, boolean isLeftShift) {

    String outputString = "";

    BigInteger[] array = stringToBigIntegerArray(text);
    String binaryString = "";
    
    for (int i = 0; i < array.length; i++) {
      String currentString = decimalToBinaryString(array[i].intValue());

      if (currentString.length() != 8) {
        currentString = prependZeros(currentString, 8);
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
    String[] shiftedBinaryStringArray = getTextAsStringArray(shiftedBinaryString, 8);

    for (int i = 0; i < shiftedBinaryStringArray.length; i++) {
      char character = (char) binaryStringToDecimal(shiftedBinaryStringArray[i]);
      outputString += character;
    }

    return outputString;
  }

  private BigInteger[] stringToBigIntegerArray(String textPart) {
    BigInteger[] array = new BigInteger[textPart.length()];

    char[] charArray = textPart.toCharArray();

    for (int i = 0; i < charArray.length; i++) {
      int val = charArray[i];
      int bac = '-';

      BigInteger bi = new BigInteger(String.valueOf(val));
      BigInteger bi_backup = new BigInteger(String.valueOf(bac));

      if (bi.bitLength() > 8) {
        array[i] = bi_backup;
      } else {
        array[i] = bi;
      }
    }

    return array;
  }

  private String[] getTextAsStringArray(String text, int tokenSize) {

    String[] story = new String[(text.length() / tokenSize) + 1];

    for (int i = 0; i < story.length; i++) {
      if (text.length() > tokenSize) {
        String subString = text.substring(0, tokenSize);
        text = text.substring(tokenSize);
        story[i] = subString;
      } else {
        text = appendWhitespaces(text, tokenSize);
        story[i] = text;
      }
    }
    return story;
  }

  private String appendWhitespaces(String textPart, int tokenSize) {
    String token = textPart;

    while (token.length() != tokenSize) {
      token = token + " ";
    }

    return token;
  }

  private static String prependZeros(String textPart, int tokenSize) {
    String token = textPart;

    while (token.length() != tokenSize) {
      token = "0" + token;
    }

    return token;
  }
  
  public BigInteger[] getKeys(String keyString) {
    BigInteger[] outputArray = new BigInteger[52];

    String key = new String(keyString);
    BigInteger[] byteKeyArray = stringToBigIntegerArray(key);
    BigInteger[] shortKeyArray = byteArrayToShortArray(byteKeyArray);

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
        byteKeyArray = stringToBigIntegerArray(key);
        shortKeyArray = byteArrayToShortArray(byteKeyArray);
      }
    }

    return outputArray;
  }

  private BigInteger[] byteArrayToShortArray(BigInteger[] array) {
    BigInteger[] outputArray = new BigInteger[array.length / 2];

    int counter = 0;
    for (int i = 0; i < outputArray.length; i++) {
      BigInteger val1 = array[counter++];
      BigInteger val2 = array[counter++];

      outputArray[i] = byteToShort(val1, val2);
    }

    return outputArray;
  }

  private BigInteger byteToShort(BigInteger val1, BigInteger val2) {
    val1 = val1.shiftLeft(8);
    return val1.add(val2);
  }

  public static String decimalToBinaryString(int val) {
    String output = "";

    while (val != 0) {
      if (val % 2 == 0) {
        output = "0" + output;
      } else {
        output = "1" + output;
      }
      val /= 2;
    }

    return output;
  }

  public static int binaryStringToDecimal(String binaryString) {
    int output = 0;
    char[] array = binaryString.toCharArray();

    for (int i = 0, j = array.length - 1; j >= 0; i++, j--) {
      if (array[j] == '1') {
        output += Math.pow(2, i);
      }
    }

    return output;
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

  private static void Logger(String event) {
    System.out.println("IDEA$  " + event);
  }
}
