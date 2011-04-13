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
   * keyword
   */
  private int[] keyword;

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

    // Frage jeweils solange die Eingabe ab, bis diese akzeptiert werden kann.
    do {
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
        System.out.println("Fehler beim Parsen des Modulus. Bitte korrigieren" + " Sie Ihre Eingabe.");
      } catch (IOException e) {
        System.err.println("Abbruch: Fehler beim Lesen von der Standardeingabe.");
        e.printStackTrace();
        System.exit(1);
      }
    } while (!accepted);
    accepted = false;
    do {
      try {
        // von string nach character array konvertieren
        String keywordString = standardInput.readLine().toString();
        char keywordChar[] = keywordString.toCharArray();

        // länge vom keyword array initialiseren
        keyword = new int[keywordChar.length];

        // konvertieren in int array
        int character;
        for (int i = 0; i < keywordChar.length; i++) {
          // konvertiere in int
          character = (int) keywordChar[i];
          character = charMap.mapChar(character);

          // check
          if (character >= 0 && character < modulus) {
            accepted = true;
          } else {
            Logger("Diese Verschiebung ist nicht geeignet. Bitte " + "korrigieren Sie Ihre Eingabe.");
          }

          // character in dem array speichern
          keyword[i] = character;
        }

      } catch (NumberFormatException e) {
        System.out.println("Fehler beim Parsen der Verschiebung. Bitte " + "korrigieren Sie Ihre Eingabe.");
      } catch (IOException e) {
        System.err.println("Abbruch: Fehler beim Lesen von der Standardeingabe.");
        e.printStackTrace();
        System.exit(1);
      }
    } while (!accepted);
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

  }

  private static void Logger(String event) {
    System.out.println(event);
  }
}
