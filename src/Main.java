import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.IIOException;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Main {

    private static final String TEXT_FILE_PATH = "lab1Text.txt";
    private static final String DES_ECB_ENCRYPTED_FILE_PATH = "lab1TextDESECBEnc.txt";
    private static final String TRIPLE_DES_ECB_ENCRYPTED_FILE_PATH = "lab1TextTripleDESECBEnc.txt";
    private static final String DES_ECB_DECRYPTED_FILE_PATH = "lab1TextDESECBEDec.txt";
    private static final String TRIPLE_DES_ECB_DECRYPTED_FILE_PATH = "lab1TextTripleDESECBDec.txt";
    private static final int WHITE_SPACE_CODE = 32;
    private static final String PIB_KEY_8 = "олеккосм";
    private static final String PIB_KEY_24 = "олеккосмюксмихайолеккосм";
    private static byte[] PIB_KEY_BYTES_8;
    private static byte[] PIB_KEY_BYTES_24;

    static {
        try {
            PIB_KEY_BYTES_8 = PIB_KEY_8.getBytes("windows-1251");
            PIB_KEY_BYTES_24 = PIB_KEY_24.getBytes("windows-1251");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            byte[] textBytes = extendByteArrayTo8BytesMultiple(readFile(TEXT_FILE_PATH));
            SecretKey pibDESECBKey = new SecretKeySpec(PIB_KEY_BYTES_8, "DES");
            Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, pibDESECBKey);
            System.out.println("Text in bytes: " + Arrays.toString(textBytes));
            System.out.println("Text: " + new String(textBytes));
            byte[] encTextBytes = cipher.doFinal(textBytes);
            writeToFile(DES_ECB_ENCRYPTED_FILE_PATH, encTextBytes);
            System.out.println("DES(ECB) encrypted text in bytes: " + Arrays.toString(encTextBytes));
            System.out.println("DES(ECB) encrypted text: " + new String(encTextBytes));
            cipher.init(Cipher.DECRYPT_MODE, pibDESECBKey);
            textBytes = cipher.doFinal(encTextBytes);
            writeToFile(DES_ECB_DECRYPTED_FILE_PATH, textBytes);
            System.out.println("DES(ECB) decrypted text in bytes: " + Arrays.toString(textBytes));
            System.out.println("DES(ECB) decrypted text: " + new String(textBytes));

            SecretKey pibTripleDESECBKey = new SecretKeySpec(PIB_KEY_BYTES_24, "TripleDES");
            cipher = Cipher.getInstance("TripleDES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, pibTripleDESECBKey);
            encTextBytes = cipher.doFinal(textBytes);
            writeToFile(TRIPLE_DES_ECB_ENCRYPTED_FILE_PATH, encTextBytes);
            System.out.println("TripleDES(ECB) encrypted text in bytes: " + Arrays.toString(encTextBytes));
            System.out.println("TripleDES(ECB) encrypted text: " + new String(encTextBytes));
            cipher.init(Cipher.DECRYPT_MODE, pibTripleDESECBKey);
            textBytes = cipher.doFinal(encTextBytes);
            writeToFile(TRIPLE_DES_ECB_DECRYPTED_FILE_PATH, textBytes);
            System.out.println("TripleDES(ECB) decrypted text in bytes: " + Arrays.toString(textBytes));
            System.out.println("TripleDES(ECB) decrypted text: " + new String(textBytes));
        } catch (IOException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException |
                IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
    }

    public static byte[] readFile(String path) throws IOException {
        return Files.readAllBytes(Paths.get(path));
    }

    public static void writeToFile(String path, byte[] bytes) throws IIOException {
        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(bytes);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException ioException) {
            ioException.printStackTrace();
        }
    }

    public static byte[] extendByteArrayTo8BytesMultiple(byte[] byteArray) {
        int length = byteArray.length;
        if (length % 8 == 0) {
            return byteArray;
        } else {
            int extendedLength = length;
            do {
                extendedLength++;
            } while (extendedLength % 8 != 0);
            byte[] extendedByteArray = new byte[extendedLength];
            for (int i = 0; i < extendedLength; i++) {
                if (i < length) {
                    extendedByteArray[i] = byteArray[i];
                } else {
                    extendedByteArray[i] = WHITE_SPACE_CODE;
                }
            }
            return extendedByteArray;
        }
    }

}
