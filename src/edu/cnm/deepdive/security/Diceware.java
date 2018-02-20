package edu.cnm.deepdive.security;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.ResourceBundle;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The <code>Diceware</code> class implements a Diceware-based passphrase generator, using a word
 * list provided in the constructor invocation. If a pseudo-random number generator is not set
 * (using the {@link Diceware#setRng(Random)} method), then an instance of {@link SecureRandom} is
 * created and used for selecting words at random from the list.
 * 
 * @author Nicholas Bennett with Deep Dive Coding Java Cohort 3
 * @version 0.9
 */
public class Diceware {

  private static final String DEFAULT_RESOURCE_BUNDLE = "wordlist";
  private static final String NEGATIVE_PASSPHRASE_MESSAGE = "Passphrase length must be positive.";
  private static final String LINE_PATTERN = "^\\s*(\\d+)\\s+(\\S+)\\s*$";

  private List<String> words;
  private Random rng = null;

  /**
   * Initializes an instance of <code>Diceware</code> using a reference to a {@link java.io.File}
   * object. If the <code>File</code> does not exist, of cannot be read, an exception will be
   * thrown.
   * 
   * @param file file to read for word list.
   * @throws FileNotFoundException if file does not exist.
   * @throws IOException if file can't be read.
   */

  public Diceware() {
    this(ResourceBundle.getBundle(DEFAULT_RESOURCE_BUNDLE));
  }

  public Diceware(File file) throws FileNotFoundException, IOException {
    words = new ArrayList<>();
    try (FileInputStream input = new FileInputStream(file);
        InputStreamReader reader = new InputStreamReader(input);
        BufferedReader buffer = new BufferedReader(reader);) {
      Pattern p = Pattern.compile(LINE_PATTERN);
      for (String line = buffer.readLine(); line != null; line = buffer.readLine()) {
        Matcher m = p.matcher(line);
        if (m.matches()) {
          words.add(m.group(2));
        }
      }
    }
  }

  /**
   * Initializes an instance of <code>Diceware</code> using a {@link Collection} as the source of
   * words for the word list.
   * 
   * @param source word list source.
   */
  public Diceware(Collection<String> source) {
    words = new ArrayList<>(source);
  }

  /**
   * Initializes an instance of <code>Diceware</code> using a {@link ResourceBundle} object as the
   * source of words for the word list. (The property values from the <code>ResourceBundle</code>
   * are taken as the words; the property names/keys are ignored.)
   * 
   * @param bundle properties provided words (values) for word list.
   */
  public Diceware(ResourceBundle bundle) {
    words = new ArrayList<>();
    Enumeration<String> en = bundle.getKeys();
    while (en.hasMoreElements()) {
      words.add(bundle.getString(en.nextElement()));
    }
  }

  /**
   * Initializes (if necessary) and returns the {@link Random} instance to be used for selecting
   * words from the word list.
   * 
   * @return pseudo-random number generator instance.
   * @throws NoSuchAlgorithmException if lazy initialization is used, and default strong provider
   *         algorithm does not exist.
   */
  public Random getRng() throws NoSuchAlgorithmException {
    if (rng == null) {
      rng = SecureRandom.getInstanceStrong();
    }
    return rng;
  }

  /**
   * Sets a reference to the {@link Random} instance to be used for selecting words from the word
   * list.
   * 
   * @param rng pseudo-random number generator instance.
   */
  public void setRng(Random rng) {
    this.rng = rng;
  }

  /**
   * Generates and returns (in a <code>String[]</code>) a password of the specified length. The
   * inclusion of duplicates is controlled by the <code>duplicatesAllowed</code> argument. If the
   * specified length is greater than the number of words in the word list, and duplicates aren't
   * allowed, then an infinite loop will result.
   * 
   * @param length number of words to include in generated passphrase.
   * @param duplicatesAllowed true if duplicate words are allowed; false otherwise.
   * @return words in generated passphrase.
   * @throws NoSuchAlgorithmException if algorithm for default strong source of randomness is not
   *         available.
   * @throws InsufficientPoolException if password length exceeds word list, and duplicates not
   *         allowed or word list has no words.
   * @throws IllegalArgumentException if requested length is not positive.
   */
  public String[] generate(int length, boolean duplicatesAllowed)
      throws NoSuchAlgorithmException, InsufficientPoolException, IllegalArgumentException {
    if (length <= 0) {
      throw new IllegalArgumentException(NEGATIVE_PASSPHRASE_MESSAGE);
    }
    if ((words.size() == 0 && length > 0) || (!duplicatesAllowed && length > words.size())) {
      throw new InsufficientPoolException();
    }
    List<String> passphrase = new LinkedList<>();
    while (passphrase.size() < length) {
      String word = generate();
      if (duplicatesAllowed || !passphrase.contains(word)) {
        passphrase.add(word);
      }
    }
    return passphrase.toArray(new String[passphrase.size()]);
  }

  /**
   * Generates and returns (in a <code>String[]</code>) a password of the specified length. This
   * method simply invokes {@link #generate(int, boolean) generate(length, true)} &ndash; that is,
   * it invokes {@link #generate(int, boolean)}, specifying that duplicates are allowed.
   * 
   * @param length number of words to include in generated passphrase.
   * @return words in generated passphrase.
   * @throws NoSuchAlgorithmException if algorithm for default strong source of randomness is not
   *         available.
   * @throws InsufficientPoolException if word list has no words.
   * @throws IllegalArgumentException if requested length is negative.
   */
  public String[] generate(int length)
      throws NoSuchAlgorithmException, InsufficientPoolException, IllegalArgumentException {
    return generate(length, true);
  }

  public String generate(int length, String delimiter)
      throws InsufficientPoolException, NoSuchAlgorithmException, IllegalArgumentException {
    return generate(length, delimiter, true);
  }

  public String generate(int length, String delimiter, boolean duplicatesAllowed)
      throws InsufficientPoolException, NoSuchAlgorithmException, IllegalArgumentException {
    String[] words = generate(length, duplicatesAllowed);
    StringBuilder builder = new StringBuilder(words[0]);
    for (int i = 1; i < words.length; i++) {
      builder.append(delimiter);
      builder.append(words[i]);
    }
    return builder.toString();
  }

  private String generate() throws NoSuchAlgorithmException {
    int index = getRng().nextInt(words.size());
    return words.get(index);
  }

  public static class InsufficientPoolException extends IllegalArgumentException {

    private InsufficientPoolException() {

    }

  }

}
