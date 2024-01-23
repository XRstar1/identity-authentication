package xu;
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
public class xu {
    public xu() {
    }

    public static void setup(String pairingFile, String publicFile, String mskFile) {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        Element s = bp.getZr().newRandomElement().getImmutable();
        Properties mskProp = new Properties();
        mskProp.setProperty("s", Base64.getEncoder().encodeToString(s.toBytes()));
        storePropToFile(mskProp, mskFile);
        Element P = bp.getG1().newRandomElement().getImmutable();
        Element P_pub = P.powZn(s).getImmutable();
        Properties pubProp = new Properties();
        pubProp.setProperty("P", Base64.getEncoder().encodeToString(P.toBytes()));
        pubProp.setProperty("P_pub", Base64.getEncoder().encodeToString(P_pub.toBytes()));
        storePropToFile(pubProp, publicFile);
    }

    public static void registration(String pairingFile, String publicFile, String mskFile, String id, String pkFile, String skFile, String pidFile) throws NoSuchAlgorithmException, IOException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String PubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PubStr)).getImmutable();
        Properties mskPro = loadPropFromFile(mskFile);
        String mskStr = mskPro.getProperty("s");
        Element s = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(mskStr)).getImmutable();
        Element r = bp.getZr().newRandomElement().getImmutable();
        Element R = P.powZn(r).getImmutable();
       // String pi = "1年";
       // byte[] h0_hash = sha1(pi + P_pub.toString() + R.powZn(s));
     //   byte[] IDByte = id.getBytes();
       // byte[] PidByte = new byte[IDByte.length];

        //for(int j = 0; j < IDByte.length; ++j) {
         //   PidByte[j] = (byte)(IDByte[j] ^ h0_hash[j]);
       // }

        //String Pid = new String(PidByte, "utf-8");
       // Element a = bp.getZr().newRandomElement().getImmutable();
       // Element T = P.powZn(a).getImmutable();

        Element x = bp.getZr().newRandomElement().getImmutable();
            Element X = P.powZn(x).getImmutable();
        byte[] h1_hash = sha1(id + R.toString() + X.toString());
        Element h1 = bp.getZr().newElementFromHash(h1_hash, 0, h1_hash.length).getImmutable();
        Element y = r.add(s.mul(h1)).getImmutable();
            FileReader SkReader = new FileReader(skFile);
            Properties skstore = new Properties();
            skstore.load(SkReader);
            skstore.setProperty("x" + id, Base64.getEncoder().encodeToString(x.toBytes()));
            skstore.setProperty("y" + id, Base64.getEncoder().encodeToString(y.toBytes()));
            FileReader PkReader = new FileReader(pkFile);
            Properties pkstore = new Properties();
            pkstore.load(PkReader);
            pkstore.setProperty("X" + id, Base64.getEncoder().encodeToString(X.toBytes()));
            pkstore.setProperty("R" + id, Base64.getEncoder().encodeToString(R.toBytes()));
         FileReader pidReader = new FileReader(pidFile);
           Properties pidPro = new Properties();
           pidPro.load(pidReader);
          pidPro.setProperty("id" + id, Base64.getEncoder().encodeToString(id.getBytes()));
            FileWriter skWriter = new FileWriter(skFile);
            FileWriter pkWriter = new FileWriter(pkFile);
            FileWriter pidWriter = new FileWriter(pidFile);
            skstore.store(skWriter, "新增sk信息");
            pkstore.store(pkWriter, "新增pk消息");
           pidPro.store(pidWriter, "新增pid消息");
            SkReader.close();
            PkReader.close();
           pidReader.close();
            skWriter.close();
            pkWriter.close();


    }

    public static void Join(String pairFile, String publicFile, String pidFile, String skFile, String pkFile, String message, String signCryptFile) throws NoSuchAlgorithmException, IOException {
        Pairing bp = PairingFactory.getPairing(pairFile);
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();
        Properties skProp = loadPropFromFile(skFile);
        String xStr = skProp.getProperty("xsend");
        String yStr = skProp.getProperty("ysend");
        Element xi = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xStr)).getImmutable();
        Element yi = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(yStr)).getImmutable();
        Properties pkProp = loadPropFromFile(pkFile);
        String XiStr = pkProp.getProperty("Xsend");
        String XjStr = pkProp.getProperty("Xrec");
        String RiStr = pkProp.getProperty("Rsend");
        String RjStr = pkProp.getProperty("Rrec");
        Element Xi = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(XiStr)).getImmutable();
        Element Xj = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(XjStr)).getImmutable();
        Element Ri = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RiStr)).getImmutable();
        Element Rj = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RjStr)).getImmutable();
        Properties pidPro = loadPropFromFile(pidFile);
       String idi = pidPro.getProperty("idsend");
      String idj = pidPro.getProperty("idrec");
        Element a = bp.getZr().newRandomElement().getImmutable();
        Element A = P.powZn(a).getImmutable();
        Element b = bp.getZr().newRandomElement().getImmutable();
        Element B = P.powZn(b).getImmutable();
        byte[] h_hash = sha1(idj + Rj.toString() + Xj.toString());
        Element h = bp.getZr().newElementFromHash(h_hash, 0, h_hash.length).getImmutable();
        Element M = (P_pub.powZn(h).add(Rj).add(Xj)).powZn(b);
        byte[] h2_hash = sha1(M.toString() + idi + A.toString());
        Element h2 = bp.getZr().newElementFromHash(h2_hash, 0, h_hash.length).getImmutable();
        byte[] h3_hash = sha1(Ri.toString() + idi + A.toString());
        Element h3 = bp.getZr().newElementFromHash(h3_hash, 0, h3_hash.length).getImmutable();
        Element sigma = a.mul(h3).add(yi).add(xi);

        /*byte[] hi_hash = sha1(pidi + Ti.toString() + P.toString() + P_pub.toString());
        Element hi = bp.getZr().newElementFromHash(hi_hash, 0, hi_hash.length).getImmutable();
        Element U_ = Qi.add(Ti.add(P_pub.powZn(hi))).powZn(u);
        byte[] hj_hash = sha1(pidj + Tj.toString() + P.toString() + P_pub.toString());
        Element hj = bp.getZr().newElementFromHash(hj_hash, 0, hj_hash.length).getImmutable();
        Element V = Qj.powZn(hj).add(Tj.powZn(hi).add(P_pub.powZn(hj).powZn(hi))).powZn(u.mul(xi.add(di)));
        byte[] Y_hash = sha1(pidj + U_.toString() + V.toString());
        System.out.println(V);
        byte[] messageByte = message.getBytes();
        byte[] c = new byte[messageByte.length];

        for(int j = 0; j < messageByte.length; ++j) {
            c[j] = (byte)(messageByte[j] ^ Y_hash[j]);
        }

        Element k = bp.getZr().newRandomElement().getImmutable();
        Element I = P.powZn(k).getImmutable();
        byte[] h3_hash = sha1(I.toString() + c.toString());
        Element r = bp.getZr().newElementFromHash(h3_hash, 0, h3_hash.length);
        Element tha = hi.mul(xi).add(hj.mul(di)).mul(r).add(k);*/
        Properties sigC = new Properties();
        sigC.setProperty("B", Base64.getEncoder().encodeToString(B.toBytes()));
       // sigC.setProperty("h", Base64.getEncoder().encodeToString(h.toBytes()));
        sigC.setProperty("A", Base64.getEncoder().encodeToString(A.toBytes()));
        sigC.setProperty("N", Base64.getEncoder().encodeToString(h2.toBytes()));
        sigC.setProperty("sigma", Base64.getEncoder().encodeToString(sigma.toBytes()));
        storePropToFile(sigC, signCryptFile);
    }

    public static void Authentication(String pairingFile, String publicFile, String pidFile, String skFile, String pkFile, String signCryptFile, String message) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();
        Properties pidProp = loadPropFromFile(pidFile);
        String idj = pidProp.getProperty("idsend");
        String idi = pidProp.getProperty("idrec");
        Properties skProp = loadPropFromFile(skFile);
        String xjStr = skProp.getProperty("xrec");
        String yjStr = skProp.getProperty("yrec");
        Element xj = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xjStr)).getImmutable();
        Element yj = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(yjStr)).getImmutable();
        Properties pkProp = loadPropFromFile(pkFile);
        String XiStr = pkProp.getProperty("Xsend");
        String RiStr = pkProp.getProperty("Rsend");
        String XjStr = pkProp.getProperty("Xrec");
        String RjStr = pkProp.getProperty("Rrec");
        Element Xi = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(XiStr)).getImmutable();
        Element Xj = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(XjStr)).getImmutable();
        Element Ri = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RiStr)).getImmutable();
        Element Rj = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RjStr)).getImmutable();
        Properties sigC = loadPropFromFile(signCryptFile);
        String BStr = sigC.getProperty("B");
        String NStr = sigC.getProperty("N");
        String AStr = sigC.getProperty("A");
        String hStr = sigC.getProperty("h");
        String sigmaStr = sigC.getProperty("sigma");

        Element B = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(BStr)).getImmutable();
        Element A = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(AStr)).getImmutable();
        Element N = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(NStr)).getImmutable();
        Element sigma = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sigmaStr)).getImmutable();
       // Element h = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(hStr)).getImmutable();

        byte[] h1_hash = sha1(idi + Ri.toString() + Xi.toString());
        Element h1 = bp.getZr().newElementFromHash(h1_hash, 0, h1_hash.length).getImmutable();
        Element M2 =B.powZn(xj.add(yj));
        Element W = P_pub.powZn(h1).add(Xi.add(Ri));
        byte[] h3_hash = sha1(Ri.toString() + idi + A.toString());
        Element h3 = bp.getZr().newElementFromHash(h3_hash, 0, h3_hash.length).getImmutable();
        Element sigma2 = A.powZn(h3).add(W);


       /* byte[] hi_hash = sha1(pidi + Ti.toString() + P.toString() + P_pub.toString());
        Element hi = bp.getZr().newElementFromHash(hi_hash, 0, hi_hash.length).getImmutable();
        byte[] hj_hash = sha1(pidj + Tj.toString() + P.toString() + P_pub.toString());
        Element hj = bp.getZr().newElementFromHash(hj_hash, 0, hj_hash.length).getImmutable();
        Element Z = U_.powZn(hj.mul(xj).add(hi.mul(dj)));
        System.out.println(Z);
        byte[] Y = sha1(pidj + U_.toString() + Z.toString());
        Element I_ = P.powZn(tha).sub(Qi.powZn(r.mul(hi))).sub(Ti.powZn(r.mul(hj))).sub(P_pub.powZn(r.mul(hi.mul(hj))));
        byte[] h3_hash = sha1(I_.toString() + c.toString());
        Element h3 = bp.getZr().newElementFromHash(h3_hash, 0, h3_hash.length);*/
        if (sigma.equals(sigma2)) {
            Element d = bp.getZr().newRandomElement().getImmutable();
            Element  D = P.powZn(d).getImmutable();


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
        String dir = "database/xu/";
        String pairingParametersFileName = "database/xu/a.properties";
        String publicParameterFileName = dir + "pub.properties";
        String pidFileName = dir + "pid.properties";
        String mskFileName = dir + "msk.properties";
        String pkFileName = dir + "pk.properties";
        String skFileName = dir + "sk.properties";
        String signCryptFileName = dir + "signCrypt.properties";

        long start = System.currentTimeMillis();
        setup(pairingParametersFileName, publicParameterFileName, mskFileName);

        for(int i = 0; i < users.length; ++i) {
            registration(pairingParametersFileName, publicParameterFileName, mskFileName, users[i], pkFileName, skFileName, pidFileName);
        }

        Join(pairingParametersFileName, publicParameterFileName, pidFileName, skFileName, pkFileName, message, signCryptFileName);
        Authentication(pairingParametersFileName, publicParameterFileName, pidFileName, skFileName, pkFileName, signCryptFileName, message);
        long end = System.currentTimeMillis();
        System.out.print("运行时间为");
        System.out.println((end - start) );
    }
}
