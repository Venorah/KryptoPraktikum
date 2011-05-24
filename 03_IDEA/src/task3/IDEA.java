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
import java.io.StringWriter;
import java.math.BigInteger;
import java.util.Iterator;
import java.util.LinkedList;
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
  static BigInteger[][] encKeys;
  static BigInteger[][] decKeys;

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

      keyString = new String(key.readLine());

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

    // generate keys
    Logger("keyString = " + keyString);
//    BigInteger[] keyArray = Helper.stringToBigIntegerArray(keyString);
    BigInteger keyInteger = Helper.stringToBigInteger(keyString);
    
    BigInteger[] keyArray = Helper.extractValues(keyInteger, 8, 16);

    
    
    
//    
//    BigInteger val1 = new BigInteger("281483566841860");
//    val1 = val1.shiftLeft(64);
//    BigInteger val2 = new BigInteger("1407400653815816");
//    BigInteger keyGen = val1.add(val2);
//    BigInteger[] keyArray = Helper.extractValues(keyGen, 8, 16);
//    
    
    

    encKeys = getEncryptionKeys(keyArray);
    decKeys = getDecryptionKeys(encKeys);

    String[] message = Helper.getTextAsStringArray(clearTextString, 8);
    Logger("message = ");

    BigInteger[] messageArray = new BigInteger[message.length]; // 64-bit blöcke
    for (int i = 0; i < message.length; i++) {
      messageArray[i] = Helper.stringToBigInteger(message[i]);

      Logger(message[i]);
      Logger(""+messageArray[i]);
    }

    BigInteger iv = new BigInteger("ddc3a8f6c66286d2", 16); // as hex
    // BigInteger iv = new BigInteger("5c7119dd40913232", 16); // as hex

    // do cbc!
    BigInteger output[] = cbcLoop(messageArray, iv, true); // output array mit 64-bit blöcken

    Logger("output");
    String outputString = "";
    for (int i = 0; i < output.length; i++) {
      if (i != output.length) {
        outputString += output[i].toString(16) + " ";
        // outputString += Helper.printAsHEX(output, 16) + " ";
      } else {
        outputString += output[i].toString(16);
        // outputString += Helper.printAsHEX(output, 16);
      }
    }
    System.out.println(outputString);

    try {
      ciphertext.write(outputString.getBytes());
    } catch (IOException e1) {
      System.out.println("Failed at FileOutputStream");
      e1.printStackTrace();
    }

    try {
      cleartext.close();
      ciphertext.close();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  public void decipher(FileInputStream ciphertext, FileOutputStream cleartext) {
    String cipherTextString = Helper.getTextAsString(ciphertext);

    // generate keys
    System.out.println(keyString);
    BigInteger[] keyArray = Helper.stringToBigIntegerArray(keyString);
    encKeys = getEncryptionKeys(keyArray);
    decKeys = getDecryptionKeys(encKeys);

    BigInteger[] messageArray = Helper.stringToBigIntegerArray(cipherTextString);
    String iv = "ddc3a8f6c66286d2"; // as hex

    BigInteger output[] = cipherBlockChaining(messageArray, iv, false);
    // System.out.println(output);

    try {
      cleartext.write(Helper.bigIntegerArraySum(output).toByteArray());
    } catch (IOException e1) {
      System.out.println("Failed at FileOutputStream");
      e1.printStackTrace();
    }

    try {
      cleartext.close();
      ciphertext.close();
    } catch (IOException e) {
      e.printStackTrace();
    }

  }

  public BigInteger cbcBlock(BigInteger message, BigInteger iv, boolean isEncryption) {
    // message xor iv
    BigInteger input = message.xor(iv);

    // make 4*16bit block array
    BigInteger[] inputArray = Helper.extractValues(input, 16, 4);

    // encryption with idea
    BigInteger outputArray[] = idea(inputArray, isEncryption);
    
    // from 4*16bit block array to one biginteger
    BigInteger output = Helper.bigIntegerArraySum(outputArray);

    return output;
  }

  public BigInteger[] cbcLoop(BigInteger[] message, BigInteger iv, boolean isEncryption) {
    BigInteger[] outputArray = new BigInteger[message.length];

    for (int i = 0; i < message.length; i++) {
      outputArray[i] = cbcBlock(message[i], iv, isEncryption);
      iv = outputArray[i];
    }

    return outputArray;
  }

  public BigInteger[] idea(BigInteger[] messagePart, boolean isEncryption) {
    BigInteger[] key = null;
    for (int round = 0; round < 9; round++) {
      // keys based on encryption or decryption
      if (isEncryption) {
        key = encKeys[round];
      } else {
        key = decKeys[round];
      }

      // encryption/decryption
      messagePart = feistelNetwork(messagePart, key, round);
      
      Logger("key round "+round);
      System.out.println(Helper.printAsHEX(key, 4));

      System.out.println(Helper.printAsHEX(messagePart, 4));
    }

    return messagePart;
  }

  private BigInteger xor(BigInteger a, BigInteger b) {
    return a.xor(b);
  }

  private BigInteger add(BigInteger a, BigInteger b) {
    BigInteger addMod = new BigInteger("65536"); // 2^16

    return a.add(b).mod(addMod);
  }

  private BigInteger multiply(BigInteger a, BigInteger b) {
    BigInteger addMod = new BigInteger("65536"); // 2^16
    BigInteger multMod = new BigInteger("65537"); // (2^16)+1

    if (a.intValue() == 0) {
      a = addMod;
    }
    if (b.intValue() == 0) {
      b = addMod;
    }

    BigInteger ret = a.multiply(b).mod(multMod);
    if (ret.compareTo(addMod) == 0) {
      return new BigInteger("0");
    } else {
      return ret;
    }
  }

  /**
   * 
   * @param input
   * @param round
   *          0-8 = 9 Rounds possible
   * @param isEnc
   *          switch for enc/dec
   * @return
   */
  public BigInteger[] feistelNetwork(BigInteger[] M, BigInteger[] K, int round) {
    BigInteger[] output = new BigInteger[4];

    if (round < 8) {

      BigInteger[] calc = new BigInteger[14];

      calc[0] = multiply(K[0], M[0]);
      calc[1] = add(K[1], M[1]);
      calc[2] = add(K[2], M[2]);
      calc[3] = multiply(K[3], M[3]);
      calc[4] = xor(calc[0], calc[2]);
      calc[5] = xor(calc[1], calc[3]);
      calc[6] = multiply(K[4], calc[4]);
      calc[7] = add(calc[6], calc[5]);
      calc[8] = multiply(K[5], calc[7]);
      calc[9] = add(calc[8], calc[6]);
      calc[10] = xor(calc[8], calc[0]);
      calc[11] = xor(calc[8], calc[2]);
      calc[12] = xor(calc[9], calc[1]);
      calc[13] = xor(calc[9], calc[3]);

      output[0] = calc[10];
      output[1] = calc[11];
      output[2] = calc[12];
      output[3] = calc[13];

    } else {

      BigInteger[] calc = new BigInteger[4];

      calc[0] = multiply(K[0], M[0]);
      calc[1] = add(K[1], M[2]);
      calc[2] = add(K[2], M[1]);
      calc[3] = multiply(K[3], M[3]);

      output[0] = calc[0];
      output[1] = calc[1];
      output[2] = calc[2];
      output[3] = calc[3];
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

  public BigInteger[][] getEncryptionKeys(BigInteger[] keyArray) {
    // String keyString
    BigInteger[] outputArray = new BigInteger[52];

    // BigInteger[] keyArray = Helper.stringToBigIntegerArray(keyString);
    BigInteger key = Helper.bigIntegerArraySum(keyArray);

    BigInteger[] shortKeyArray = Helper.extractValues(key, 16, 8);

    // get keys
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

    // get as 2d array
    BigInteger[][] nicerArray = new BigInteger[9][6];

    int counter = 0;
    for (int zeile = 0; zeile < nicerArray.length; zeile++) {
      for (int spalte = 0; spalte < nicerArray[zeile].length; spalte++) {
        nicerArray[zeile][spalte] = outputArray[counter++];
        if (counter == 52) {
          return nicerArray;
        }
      }
    }

    return nicerArray;
  }

  public BigInteger[][] getDecryptionKeys(BigInteger[][] encryptionKeys) {
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

  private void Logger(String event) {
    System.out.println("IDEA$  " + event);
  }
}
