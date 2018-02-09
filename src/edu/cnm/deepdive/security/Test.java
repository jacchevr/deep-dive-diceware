package edu.cnm.deepdive.security;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.ResourceBundle;

public class Test {

  public static void main(String[] args) 
      throws FileNotFoundException, NoSuchAlgorithmException, IOException {
//    File file = new File("eff_large_wordlist.txt");
//    Diceware dw = new Diceware(file);
    try {
//      ResourceBundle bundle = ResourceBundle.getBundle("wordlist"); 
//      Diceware dw = new Diceware(bundle);
      Diceware dw = new Diceware(Arrays.asList(new String[] {"the", "quick", "brown", "fox"}));
      String[] passphrase = dw.generate(-5, false);
      System.out.println(Arrays.toString(passphrase));
    } catch (Diceware.InsufficientPoolException ex) {
      System.out.println("Not enough words in the word list.");
    } catch (IllegalArgumentException ex) {
      // TODO Assume we've logged this or done something else interesting with ex.
      throw ex;
//      System.out.println("You can't have a negative-length passphrase!!!!");
    } finally {
      System.out.println("Well, now we're done.");
    }
  }

}
