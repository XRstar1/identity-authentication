package Jia2;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;
public class Jia2 {
    public Jia2() {
    }

    public static void setup(String pairingFile, String publicFile, String mskFile) {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        Element s = bp.getZr().newRandomElement().getImmutable();
        Element s2 = bp.getZr().newRandomElement().getImmutable();
        Properties mskProp = new Properties();
        mskProp.setProperty("s", Base64.getEncoder().encodeToString(s.toBytes()));
        mskProp.setProperty("s2", Base64.getEncoder().encodeToString(s2.toBytes()));
        storePropToFile(mskProp, mskFile);
        Element P = bp.getG1().newRandomElement().getImmutable();
        Element P_pub = P.powZn(s).getImmutable();
        Element P_pub2 = P.powZn(s2).getImmutable();
        Element g = bp.pairing(P,P);
        Properties pubProp = new Properties();
        pubProp.setProperty("P", Base64.getEncoder().encodeToString(P.toBytes()));
        pubProp.setProperty("P_pub", Base64.getEncoder().encodeToString(P_pub.toBytes()));
        pubProp.setProperty("P_pub2", Base64.getEncoder().encodeToString(P_pub2.toBytes()));
        pubProp.setProperty("g", Base64.getEncoder().encodeToString(g.toBytes()));
        storePropToFile(pubProp, publicFile);
    }

    public static void registration1(String pairingFile, String publicFile, String mskFile, String id, String pkFile, String skFile, String pidFile) throws NoSuchAlgorithmException, IOException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String PubStr = pubProp.getProperty("P_pub");
        String Pub2Str = pubProp.getProperty("P_pub2");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PubStr)).getImmutable();
        Element P_pub2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Pub2Str)).getImmutable();
        Properties mskPro = loadPropFromFile(mskFile);
        String mskStr = mskPro.getProperty("s");
        String msk2Str = mskPro.getProperty("s2");
        Element s2 = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(msk2Str)).getImmutable();
        Element s = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(mskStr)).getImmutable();
        Element r = bp.getZr().newRandomElement().getImmutable();
        Element R = P.powZn(r).getImmutable();

        byte[] h1_hash = sha1(id + R.toString() );
        Element h1 = bp.getZr().newElementFromHash(h1_hash, 0, h1_hash.length).getImmutable();
        Element SIDu = r.add(s.mul(h1)).getImmutable();
        FileReader SkReader = new FileReader(skFile);
        Properties skstore = new Properties();
        skstore.load(SkReader);
        skstore.setProperty("R" + id, Base64.getEncoder().encodeToString(R.toBytes()));
        skstore.setProperty("SIDu" + id, Base64.getEncoder().encodeToString(SIDu.toBytes()));

        FileReader pidReader = new FileReader(pidFile);
        Properties pidPro = new Properties();
        pidPro.load(pidReader);
        pidPro.setProperty("id" + id, Base64.getEncoder().encodeToString(id.getBytes()));
        FileWriter skWriter = new FileWriter(skFile);

        FileWriter pidWriter = new FileWriter(pidFile);
        skstore.store(skWriter, "新增sk信息");

        pidPro.store(pidWriter, "新增pid消息");
        SkReader.close();

        pidReader.close();
        skWriter.close();

    }

    public static void registration2(String pairingFile, String publicFile, String mskFile, String id, String pkFile, String skFile, String pidFile) throws NoSuchAlgorithmException, IOException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String PubStr = pubProp.getProperty("P_pub");
        String Pub2Str = pubProp.getProperty("P_pub2");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PubStr)).getImmutable();
        Element P_pub2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Pub2Str)).getImmutable();
        Properties mskPro = loadPropFromFile(mskFile);
        String mskStr = mskPro.getProperty("s");
        String msk2Str = mskPro.getProperty("s2");
        Element s2 = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(msk2Str)).getImmutable();
        Element s = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(mskStr)).getImmutable();
        Element r = bp.getZr().newRandomElement().getImmutable();
        Element R = P.powZn(r).getImmutable();

        byte[] h1_hash = sha1(id);
        Element h1 = bp.getZr().newElementFromHash(h1_hash, 0, h1_hash.length).getImmutable();
        Element SIDm = P.powZn(s2.add(h1).invert()).getImmutable();

        FileReader SkReader = new FileReader(skFile);
        Properties skstore = new Properties();
        skstore.load(SkReader);

        skstore.setProperty("SIDm" + id, Base64.getEncoder().encodeToString(SIDm.toBytes()));

        FileReader pidReader = new FileReader(pidFile);
        Properties pidPro = new Properties();
        pidPro.load(pidReader);
        pidPro.setProperty("id" + id, Base64.getEncoder().encodeToString(id.getBytes()));
        FileWriter skWriter = new FileWriter(skFile);

        FileWriter pidWriter = new FileWriter(pidFile);
        skstore.store(skWriter, "新增sk信息");
        pidPro.store(pidWriter, "新增pid消息");
        SkReader.close();
        pidReader.close();
        skWriter.close();



    }





    public static void Join(String pairFile, String publicFile, String pidFile, String skFile, String pkFile, String message, String signCryptFile) throws NoSuchAlgorithmException, IOException {
        Pairing bp = PairingFactory.getPairing(pairFile);
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String gStr = pubProp.getProperty("g");
        String PpubStr = pubProp.getProperty("P_pub");
        String Ppub2Str = pubProp.getProperty("P_pub2");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();
        Element P_pub2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Ppub2Str)).getImmutable();
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gStr)).getImmutable();
        Properties skProp = loadPropFromFile(skFile);
        String RStr = skProp.getProperty("Rsend");
        String SIDuStr = skProp.getProperty("SIDusend");
        Element R = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RStr)).getImmutable();
        Element SIDu = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(SIDuStr)).getImmutable();

        Properties pidPro = loadPropFromFile(pidFile);
        String idi = pidPro.getProperty("idsend");
        String idj = pidPro.getProperty("idrec");
        Element x = bp.getZr().newRandomElement().getImmutable();
        Element X = P.powZn(x).getImmutable();
        Element gx = g.powZn(x).getImmutable();
        byte[] h1_hash = sha1(idj);
        Element h1 = bp.getZr().newElementFromHash(h1_hash, 0, h1_hash.length).getImmutable();
        byte[] h2_hash = sha1(gx.toString()+idi+R.toString()+X.toString());
        Element N = bp.getZr().newElementFromHash(h2_hash, 0, h2_hash.length).getImmutable();
        Element M = P.powZn(h1).add(P_pub2).powZn(x).getImmutable();
        byte[] h3_hash = sha1(idi+R.toString()+X.toString());
        Element h3 = bp.getZr().newElementFromHash(h3_hash, 0, h3_hash.length).getImmutable();
        Element sigma = SIDu.add(x.mul(h3));
        byte[] h0_hash = sha1(idi+R.toString());
        Element h0 = bp.getZr().newElementFromHash(h0_hash, 0, h0_hash.length).getImmutable();




        Properties sigC = new Properties();
        sigC.setProperty("M", Base64.getEncoder().encodeToString(M.toBytes()));
        sigC.setProperty("h0", Base64.getEncoder().encodeToString(h0.toBytes()));
        sigC.setProperty("X", Base64.getEncoder().encodeToString(X.toBytes()));
        sigC.setProperty("N", Base64.getEncoder().encodeToString(N.toBytes()));
        sigC.setProperty("sigma", Base64.getEncoder().encodeToString(sigma.toBytes()));
        storePropToFile(sigC, signCryptFile);
    }

    public static void Authentication(String pairingFile, String publicFile, String pidFile, String skFile, String pkFile, String signCryptFile, String message) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String gStr = pubProp.getProperty("g");
        String PpubStr = pubProp.getProperty("P_pub");
        String Ppub2Str = pubProp.getProperty("P_pub2");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();
        Element P_pub2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Ppub2Str)).getImmutable();
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gStr)).getImmutable();
        Properties pidProp = loadPropFromFile(pidFile);
        String idj = pidProp.getProperty("idsend");
        String idi = pidProp.getProperty("idrec");
        Properties skProp = loadPropFromFile(skFile);
        String SIDmStr = skProp.getProperty("SIDmrec");
        Element SIDm = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(SIDmStr)).getImmutable();
        String RStr = skProp.getProperty("Rsend");
        String SIDuStr = skProp.getProperty("SIDusend");
        Element R = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RStr)).getImmutable();

        Properties sigC = loadPropFromFile(signCryptFile);
        String MStr = sigC.getProperty("M");
        String NStr = sigC.getProperty("N");
        String AStr = sigC.getProperty("X");
        String h0Str = sigC.getProperty("h0");
        String sigmaStr = sigC.getProperty("sigma");

        Element M = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(MStr)).getImmutable();
        Element X = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(AStr)).getImmutable();
        Element N = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(NStr)).getImmutable();
        Element sigma = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sigmaStr)).getImmutable();
        Element h0 = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(h0Str)).getImmutable();


        Element W = R.add(P_pub.powZn(h0));
        byte[] h3_hash = sha1(idi+R.toString()+X.toString());
        Element h3 = bp.getZr().newElementFromHash(h3_hash, 0, h3_hash.length).getImmutable();
        Element sigma2 = W.add(X.powZn(h3));






        if (sigma.equals(sigma2)) {
            Element y = bp.getZr().newRandomElement().getImmutable();
            Element  Y = P.powZn(y).getImmutable();

        }

    }

    public static void storePropToFile(Properties prop, String fileName) {
        try {
            FileOutputStream out = new FileOutputStream(fileName);
            Throwable var3 = null;

            try {
                prop.store(out, (String)null);
            } catch (Throwable var13) {
                var3 = var13;
                throw var13;
            } finally {
                if (out != null) {
                    if (var3 != null) {
                        try {
                            out.close();
                        } catch (Throwable var12) {
                            var3.addSuppressed(var12);
                        }
                    } else {
                        out.close();
                    }
                }

            }
        } catch (IOException var15) {
            var15.printStackTrace();
            System.out.println(fileName + " save failed!");
            System.exit(-1);
        }

    }

    public static Properties loadPropFromFile(String fileName) {
        Properties prop = new Properties();

        try {
            FileInputStream in = new FileInputStream(fileName);
            Throwable var3 = null;

            try {
                prop.load(in);
            } catch (Throwable var13) {
                var3 = var13;
                throw var13;
            } finally {
                if (in != null) {
                    if (var3 != null) {
                        try {
                            in.close();
                        } catch (Throwable var12) {
                            var3.addSuppressed(var12);
                        }
                    } else {
                        in.close();
                    }
                }

            }
        } catch (IOException var15) {
            var15.printStackTrace();
            System.out.println(fileName + " load failed!");
            System.exit(-1);
        }

        return prop;
    }

    public static byte[] sha1(String content) throws NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("SHA-1");
        instance.update(content.getBytes());
        return instance.digest();
    }

    public static void main(String[] args) throws Exception {
        String message = "12345678";
        String[] users = new String[]{"send", "rec"};
        String dir = "database/Jia2/";
        String pairingParametersFileName = "database/Jia2/a.properties";
        String publicParameterFileName = dir + "pub.properties";
        String pidFileName = dir + "pid.properties";
        String mskFileName = dir + "msk.properties";
        String pkFileName = dir + "pk.properties";
        String skFileName = dir + "sk.properties";
        String signCryptFileName = dir + "signCrypt.properties";
        long start = System.currentTimeMillis();
        setup(pairingParametersFileName, publicParameterFileName, mskFileName);


        registration1(pairingParametersFileName, publicParameterFileName, mskFileName,users[0], pkFileName, skFileName, pidFileName);
        registration2(pairingParametersFileName, publicParameterFileName, mskFileName,users[1], pkFileName, skFileName, pidFileName);

        Join(pairingParametersFileName, publicParameterFileName, pidFileName, skFileName, pkFileName, message, signCryptFileName);
        Authentication(pairingParametersFileName, publicParameterFileName, pidFileName, skFileName, pkFileName, signCryptFileName, message);
        long end = System.currentTimeMillis();
        System.out.print("运行时间为");
        System.out.println((end - start) * 10L);
    }
}
