/*
 * jCrypt - Programmierumgebung für das Kryptologie-Praktikum
 * Studienarbeit am Institut für Theoretische Informatik der
 * Technischen Universität Braunschweig
 * 
 * Datei:        Vigenere.java
 * Beschreibung: Dummy-Implementierung der Vigenère-Chiffre
 * Erstellt:     30. März 2010
 * Autor:        Martin Klußmann
 */

package task1;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.util.StringTokenizer;

import de.tubs.cs.iti.jcrypt.chiffre.CharacterMapping;
import de.tubs.cs.iti.jcrypt.chiffre.Cipher;

/**
 * Dummy-Klasse für die Vigenère-Chiffre.
 * 
 * @author Martin Klußmann
 * @version 1.0 - Tue Mar 30 15:53:38 CEST 2010
 */
public class Vigenere extends Cipher {

  /**
   * Analysiert den durch den Reader <code>ciphertext</code> gegebenen Chiffretext, bricht die
   * Chiffre bzw. unterstützt das Brechen der Chiffre (ggf. interaktiv) und schreibt den Klartext
   * mit dem Writer <code>cleartext</code>.
   * 
   * @param ciphertext
   *          Der Reader, der den Chiffretext liefert.
   * @param cleartext
   *          Der Writer, der den Klartext schreiben soll.
   */
  public void breakCipher(BufferedReader ciphertext, BufferedWriter cleartext) {

  }

  /**
   * Entschlüsselt den durch den Reader <code>ciphertext</code> gegebenen Chiffretext und schreibt
   * den Klartext mit dem Writer <code>cleartext</code>.
   * 
   * @param ciphertext
   *          Der Reader, der den Chiffretext liefert.
   * @param cleartext
   *          Der Writer, der den Klartext schreiben soll.
   */
  public void decipher(BufferedReader ciphertext, BufferedWriter cleartext) {
    // Kommentierung analog 'encipher(cleartext, ciphertext)'.
    try {

      int[] keyword = new int[26];
      int character;
      int d = 0;

      while ((character = ciphertext.read()) != -1) {
        character = charMap.mapChar(character);
        if (character != -1) {

          // character = (character - shift + modulus) % modulus;
          character = (character - (keyword[d++] % keyword.length)) % modulus;

          character = charMap.remapChar(character);
          cleartext.write(character);
        } else {
          // Ein überlesenes Zeichen sollte bei korrekter Chiffretext-Datei
          // eigentlich nicht auftreten können.
        }
      }
      cleartext.close();
      ciphertext.close();
    } catch (IOException e) {
      System.err.println("Abbruch: Fehler beim Zugriff auf Klar- oder " + "Chiffretextdatei.");
      e.printStackTrace();
      System.exit(1);
    }
  }

  /**
   * Verschlüsselt den durch den Reader <code>cleartext</code> gegebenen Klartext und schreibt den
   * Chiffretext mit dem Writer <code>ciphertext</code>.
   * 
   * @param cleartext
   *          Der Reader, der den Klartext liefert.
   * @param ciphertext
   *          Der Writer, der den Chiffretext schreiben soll.
   */
  public void encipher(BufferedReader cleartext, BufferedWriter ciphertext) {
    // An dieser Stelle könnte man alle Zeichen, die aus der Klartextdatei
    // gelesen werden, in Klein- bzw. Großbuchstaben umwandeln lassen:
    // charMap.setConvertToLowerCase();
    // charMap.setConvertToUpperCase();

    int[] keyword = new int[26]; // TODO remove after pull of global variable
    int c = 0;

    try {
      int character;
      boolean characterSkipped = false;
      while ((character = cleartext.read()) != -1) {
        character = charMap.mapChar(character);
        if (character != -1) {

          // character = (character + shift) % modulus;
          character = (character + (keyword[c++] % keyword.length)) % modulus;

          character = charMap.remapChar(character);
          ciphertext.write(character);
        } else {
          // Das gelesene Zeichen ist im benutzten Alphabet nicht enthalten.
          characterSkipped = true;
        }
      }
      if (characterSkipped) {
        System.out.println("Warnung: Mindestens ein Zeichen aus der " + "Klartextdatei ist im Alphabet nicht\nenthalten und wurde " + "überlesen.");
      }
      cleartext.close();
      ciphertext.close();
    } catch (IOException e) {
      System.err.println("Abbruch: Fehler beim Zugriff auf Klar- oder " + "Chiffretextdatei.");
      e.printStackTrace();
      System.exit(1);
    }
  }

  /**
   * Erzeugt einen neuen Schlüssel.
   * 
   * @see #readKey readKey
   * @see #writeKey writeKey
   */
  public void makeKey() {

    BufferedReader standardInput = launcher.openStandardInput();
    boolean accepted = false;

    Logger("Geben Sie den Modulus ein: ");
    try {
      modulus = Integer.parseInt(standardInput.readLine());

      String defaultAlphabet = CharacterMapping.getDefaultAlphabet(modulus);
      if (!defaultAlphabet.equals("")) {
        Logger("Vordefiniertes Alphabet: '" + defaultAlphabet + "'\nDieses vordefinierte Alphabet kann durch Angabe einer " + "geeigneten Alphabet-Datei\nersetzt werden. Weitere " + "Informationen finden Sie im Javadoc der Klasse\n'Character" + "Mapping'.");
        accepted = true;
      } else {
        Logger("Warnung: Dem eingegebenen Modulus kann kein Default-" + "Alphabet zugeordnet werden.\nErstellen Sie zusätzlich zu " + "dieser Schlüssel- eine passende Alphabet-Datei.\nWeitere " + "Informationen finden Sie im Javadoc der Klasse 'Character" + "Mapping'.");
        accepted = true;
      }
    } catch (NumberFormatException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    }

    try {
      int shift = Integer.parseInt(standardInput.readLine());
      if (shift >= 0 && shift < modulus) {
        accepted = true;
      } else {
        Logger("Diese Verschiebung ist nicht geeignet. Bitte " + "korrigieren Sie Ihre Eingabe.");
      }
    } catch (NumberFormatException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (IOException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
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
      StringTokenizer st = new StringTokenizer(key.readLine(), " ");
      modulus = Integer.parseInt(st.nextToken());
      Logger("Modulus: " + modulus);

      int[] keyword = new int[26];
      int c = 0;

      while (st.hasMoreTokens()) {
        keyword[c++] = Integer.parseInt(st.nextToken());
      }
      Logger("Schluessel: " + keyword.toString());

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

      int[] keyword = new int[26];

      String keyString = "";

      for (int i = 0; i < keyword.length; i++) {
        keyString = keyString + " " + keyword[i];
      }

      key.write(modulus + keyString);

      key.newLine();
      key.close();
    } catch (IOException e) {
      System.out.println("Abbruch: Fehler beim Schreiben oder Schließen der " + "Schlüsseldatei.");
      e.printStackTrace();
      System.exit(1);
    }
  }

  private static void Logger(String event) {
    System.out.println(event);
  }
}
