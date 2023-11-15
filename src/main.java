import java.security.*;

public class main {

    public static void main(String[] args) {
        try {
            // Generate a key pair (public and private key)
            KeyPair keyPair = generateKeyPair();

            // Get the private and public keys from the key pair
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // Certificate details for Company A
            String companyName = "Company A";
            String companyCourse = "Blockchain 101";
            String companyInstructor = "Dr. Anderson";

            // Sign the message for Company A using the private key
            String messageForCompany = createMessage(companyName, companyCourse, companyInstructor);
            byte[] signatureForCompany = signMessage(messageForCompany, privateKey);

            // Verify the signatures using the public key
            boolean isSignatureForCompanyAValid = verifySignature(messageForCompany, signatureForCompany, publicKey);
            String data = "{" + companyName + " " + companyCourse + "}";
            String fingerprint = "";
            try {
                // Generate the fingerprint using SHA-256
                fingerprint = generateFingerprint(data);
            } catch (Exception e) {
                e.printStackTrace();
            }

            // Print the results
            System.out.println("Company Certificate Details:");
            System.out.println("Name: " + companyName);
            System.out.println("Course: " + companyCourse);
            System.out.println("Instructor: " + companyInstructor);
            System.out.println("Digital Signature: " + bytesToHex(signatureForCompany));
            System.out.println("Data: " + data);
            System.out.println("Fingerprint: " + fingerprint);
            System.out.println("Is Signature Valid? " + isSignatureForCompanyAValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // You can adjust the key size
        return keyPairGenerator.generateKeyPair();
    }

    private static String createMessage(String name, String course, String instructor) {
        return name + "," + course + "," + instructor;
    }

    private static byte[] signMessage(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        return signature.sign();
    }

    private static boolean verifySignature(String message, byte[] signature, PublicKey publicKey) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(message.getBytes());
        return verifier.verify(signature);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte aByte : bytes) {
            result.append(String.format("%02x", aByte));
        }
        return result.toString();
    }

    private static String generateFingerprint(String data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(data.getBytes());

        // Convert the byte array to a hexadecimal string
        StringBuilder hexFingerprint = new StringBuilder();
        for (byte hashByte : hashBytes) {
            String hex = Integer.toHexString(0xff & hashByte);
            if (hex.length() == 1) {
                hexFingerprint.append('0');
            }
            hexFingerprint.append(hex);
        }
        return hexFingerprint.toString();
    }

}