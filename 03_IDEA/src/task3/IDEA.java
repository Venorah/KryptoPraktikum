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

import de.tubs.cs.iti.jcrypt.chiffre.BlockCipher;

/**
 * Dummy-Klasse für den International Data Encryption Algorithm (IDEA).
 * 
 * @author Martin Klußmann
 * @version 1.1 - Sat Apr 03 21:57:35 CEST 2010
 */
public final class IDEA extends BlockCipher {

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

  /**
   * Erzeugt einen neuen Schlüssel.
   * 
   * @see #readKey readKey
   * @see #writeKey writeKey
   */
  public void makeKey() {

    System.out.println("Dummy für die Schlüsselerzeugung.");
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
}
