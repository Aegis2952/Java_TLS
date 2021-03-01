package com.jva.tls;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.soap.Node;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;


import org.apache.http.HttpEntity;
import org.apache.http.ParseException;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.openssl.PEMReader;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.util.ResourceUtils;

import com.jva.tls.KeyImportException;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import sun.security.util.Password;

public class KeyStoreUtil {

	public static String server_url = null;
	public static String content_type = null;
	public static String srsBackendGateway_ClientAuth = null;
	public static String x_Srs_Auth_type = null;
	public static String apiKey = null;
	public static String authorization_SRS = null;
	public static String crt_body = null;
	public static String key_FIle_Path = null;
	public static String certFilePath = null;
	public static String pass_Pharsse = null;
	

	

	public static void loadAllProperties() throws Exception {
		Properties prop = new Properties();
		prop = loadServersURL();
		server_url = prop.getProperty("SERVER_URL");
		if (server_url != null) {
			server_url = server_url.trim();
		} else {
			throw new Exception("server_url can not be null");
		}
		content_type = prop.getProperty("CONTENT_TYPE");
		if (content_type != null) {
			content_type = content_type.trim();
		}
		srsBackendGateway_ClientAuth = prop.getProperty("CLIENT_AUTH");
		if (srsBackendGateway_ClientAuth != null) {
			srsBackendGateway_ClientAuth = srsBackendGateway_ClientAuth.trim();
		}
		x_Srs_Auth_type = prop.getProperty("X_SRS_AUTH_TYPE");
		if (x_Srs_Auth_type != null) {
			x_Srs_Auth_type = x_Srs_Auth_type.trim();
		}
		apiKey = prop.getProperty("APIKEY");
		if (apiKey != null) {
			apiKey = apiKey.trim();
		}
		authorization_SRS = prop.getProperty("AUTHORIZATION_SRS");
		if (authorization_SRS != null) {
			authorization_SRS = authorization_SRS.trim();
		}
	 crt_body = "{\r\n"
				+ " \"certSigningRequest\":\"MIICRTCCAS0CAQAwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMYQeanwwNRDa9oK0fNdZ1Zn7B46MA4i6Xv3EOc+MELwzwQjkcIYEiupYwkson4HjYNgsn06HL2wDiH0VtI/rLrV+Pv78w0kw45GAjecJU7onhXfMxkGyaI3dCb1hXdr2KK25W2GQUuSpNYbPE5yb22pp6SW5FmBOUB5juXSUDyDLFXtdctzpqHRRtlCugoLCmaEQo3V/BhLOD52aJmvsrOuhWMX9ENH991tHV/wHAfsmuKJypdU5bFjFRIiN4VPVJCvpHEu7MTEVeBiWV8MJDLOlYX8mO1JPUddaPF9GU0Y5wY9DOGfMMawAQSQ9aRrdWU5takKaSFhHokg1JZ7R2ECAwEAAaAAMA0GCSqGSIb3DQEBDQUAA4IBAQAeTC9f5uwLB8iWUzCc0WmbC5OuLgjhRnetSI7hgOnWQGUcKRJcpfkkaqQc/wgoB16zvW33PUjacBDzd9V3SVjFsI6JvzmgR/ziqJv5CrJgvzXf3jJH4jPrJIyIW80eQfOEUXFujwxTYEhfIG1/bOkfLTMLYvBecIS0EaY2saVqHqXG1KnfwHUQfCXf0kdfaLOVbNg8kMYN/Hb/AB8sczjkqHOS87kxqJdgj+TBK9NVlrQPWPIM+836nXP77WNQi16LY6IXQVx4643G7muD4qLJwkJjt0QMb5qakuQ1GMdLuPHOuR5LINDLBfK4AD4GQTOS12rNhEweknjNs9t/Ctqw\",\r\n"
				+ "              \"macAddresses\":\"00:00:00:00:00:00;02:42:AC:11:00:02\",\r\n"
				+ "              \"ipAddresses\":\"127.0.0.1;172.17.0.2\",\r\n"
				+ "              \"version\" : \"4.00.05.18\"\r\n" + "              }";
	 
		key_FIle_Path = prop.getProperty("KEY_FILE_PATH");
		if (key_FIle_Path != null) {
			key_FIle_Path = key_FIle_Path.trim();
		} else {
			throw new Exception("key_FIle_Path can not be null");
		}
		certFilePath = prop.getProperty("CERT_FILE_PATH");
		if (certFilePath != null) {
			certFilePath = certFilePath.trim();
		} else {
			throw new Exception("certFilePath can not be null");
		}

		pass_Pharsse = prop.getProperty("PASS_PHRASE").trim();

		if (pass_Pharsse != null) {
			pass_Pharsse = pass_Pharsse.trim();
		} else {
			throw new Exception("Pass Phrase can not be null");
		}
	}

	public static Properties loadServersURL() throws FileNotFoundException {
		String serverURL = null;
		Properties prop = null;
		/*
		 * File resource = new FileSystemResource( "config.properties").getFile();
		 * 
		 */

		File resource = ResourceUtils.getFile("classpath:config_bootStrap.properties");
		System.out.println("config path is " + resource.getAbsolutePath());
		try (InputStream input = new FileInputStream(resource)) {

			prop = new Properties();

			// load a properties file from class path, inside static method
			prop.load(input);

		} catch (IOException ex) {
			ex.printStackTrace();
		}
		return prop;

	}

	public static PrivateKey getPrivateKey(String key_FIle_Path) throws IOException, KeyImportException, GeneralSecurityException {

		
		PrivateKey privateKey = null;
		PrivateKey privateKeyNew = null;
		try {

			 File initialFile = new File(key_FIle_Path);
			 InputStream ins = new FileInputStream(initialFile);
			BufferedReader in = new BufferedReader(new InputStreamReader(ins));
			StringBuffer base64EncodedKey = new StringBuffer();
			String line;
			
			KeyPair key = null;
			Object obj = null;
			boolean encrypted = false;
			boolean readingKey = false;
			boolean pkcs8Format = false;
			boolean rsaFormat = false;
			boolean dsaFormat = false;
			while ((line = in.readLine()) != null) {
				if (readingKey) {
					if (line.trim().equals("-----END ENCRYPTED PRIVATE KEY-----")) {
						readingKey = false;
					} else {
						base64EncodedKey.append(line.trim());
					}

				} else if (line.trim().equals("-----BEGIN ENCRYPTED PRIVATE KEY-----")) {
					readingKey = true;
					encrypted = true;
				}
			}
			if (base64EncodedKey.length() == 0) {
				throw new IOException("File '" + "file Key" + "' did not contain an unencrypted private key");
			}

			/*
			 * //=================New changes start
			 * 
			 * EncryptedPrivateKeyInfo pkInfo = new
			 * EncryptedPrivateKeyInfo(Base64.getDecoder().decode(base64EncodedKey.toString(
			 * )));
			 * 
			 * PBEKeySpec keySpec = new PBEKeySpec(pass_Pharsse.toCharArray());
			 * SecretKeyFactory pbeKeyFactory =
			 * SecretKeyFactory.getInstance(pkInfo.getAlgName());
			 * 
			 * PKCS8EncodedKeySpec encodedKeySpec1 =
			 * pkInfo.getKeySpec(pbeKeyFactory.generateSecret(keySpec)); KeyFactory
			 * keyFactory = KeyFactory.getInstance("RSA"); privateKeyNew =
			 * keyFactory.generatePrivate(encodedKeySpec1);
			 * 
			 * ////=======================New changes end
			 */
			byte[] bytes = base64Decode(base64EncodedKey.toString());
			List<BigInteger> pkcs5Integers = new ArrayList<BigInteger>();
			List<byte[]> oids = new ArrayList<byte[]>();
			List<byte[]> byteStrings = new ArrayList<byte[]>();
			ASN1Parse(bytes, pkcs5Integers, oids, byteStrings);

			byte[] salt = byteStrings.get(0);
			int iterationCount = pkcs5Integers.get(0).intValue();

			// XXX I should be verifying the key-stretching algorithm OID here
			byte[] keyd = stretchKey(pass_Pharsse, salt, iterationCount);
			byte[] encryptedBytes = byteStrings.get(2);
			byte[] iv = byteStrings.get(1);
			// XXX I should be verifying the encryption algorithm OID here
			bytes = decrypt(keyd, iv, encryptedBytes);

			final PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(bytes);
			final KeyFactory kf = KeyFactory.getInstance("RSA");
			privateKey = kf.generatePrivate(encodedKeySpec);
			
			System.out.println("privateKey" +privateKey);

		} finally {
			// close(reader);
		}
		return privateKey;
	}

	/*
	 * public static X509Certificate loadCertificate(String file) throws IOException
	 * { PEMReader reader = null; X509Certificate ret = null; try {
	 * 
	 * Object obj = null; FileReader fileReader = new FileReader(file);
	 * 
	 * 
	 * PEMReader pemReader = new PEMReader(fileReader); obj =
	 * pemReader.readObject();
	 * 
	 * ret = (X509Certificate) obj;
	 * 
	 * } finally { close(reader); } return ret; }
	 */

	

		
		
	  
	  
	 	public static X509Certificate loadCertificate(String content) throws IOException {
		PEMReader reader = null;
		X509Certificate ret = null;
		try {

			// File file = ResourceUtils.getFile("classpath:"+content);
			//logger.info("0" + content);
			//InputStream in = KeyStoreUtil.class.getClassLoader().getResourceAsStream(content);
			 File initialFile = new File(content);
			    InputStream in = new FileInputStream(initialFile);
			    
			    
			System.out.print("in---" +in.toString());
			// InputStream in = getClass().getResourceAsStream(content);
			//logger.info("inputststrea is: :" + in.toString());
			// InputStream in = new FileInputStream(file);
			Reader certData = new InputStreamReader(in);
			//logger.info("1");

			// new FileSystemResource(content).getFile();
			// FileReader fileReader = new FileReader(resource);

			Object obj = null;

			//logger.info("2");

			PEMReader pemReader = new PEMReader(certData);
			//logger.info("3");
			obj = pemReader.readObject();

			ret = (X509Certificate) obj;
			
			//System.out.print("rett--" +ret.toString());
			//logger.info("ret :" + ret);

		} finally {
			close(reader);
		}
		return ret;
	}
	
	private static void ASN1Parse(byte[] b, List<BigInteger> integers, List<byte[]> oids, List<byte[]> byteStrings)
			throws KeyImportException {
		int pos = 0;
		while (pos < b.length) {
			byte tag = b[pos++];
			int length = b[pos++];
			if ((length & 0x80) != 0) {
				int extLen = 0;
				for (int i = 0; i < (length & 0x7F); i++) {
					extLen = (extLen << 8) | (b[pos++] & 0xFF);
				}
				length = extLen;
			}
			byte[] contents = new byte[length];
			System.arraycopy(b, pos, contents, 0, length);
			pos += length;

			if (tag == 0x30) { // sequence
				ASN1Parse(contents, integers, oids, byteStrings);
			} else if (tag == 0x02) { // Integer
				BigInteger i = new BigInteger(contents);
				integers.add(i);
			} else if (tag == 0x04) { // byte string
				byteStrings.add(contents);
			} else if (tag == 0x06) { // OID
				oids.add(contents);
			} else if (tag == 0x05) { // String
// Ignore this.  It comes up in the RSA format, but only as a placeholder.
			} else {
				throw new KeyImportException(
						"Unsupported ASN.1 tag " + tag + " encountered.  Is this a " + "valid RSA key?");
			}
		}
	}

	private static byte[] stretchKey(String password, byte[] salt, int iterationCount)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, 192); // length of a DES3 key
		SecretKeyFactory fact = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

		return fact.generateSecret(pbeKeySpec).getEncoded();
	}

	private static byte[] decrypt(byte[] key, byte[] iv, byte[] encrypted) throws GeneralSecurityException {
		DESedeKeySpec desKeySpec = new DESedeKeySpec(key);
		SecretKeySpec desKey = new SecretKeySpec(desKeySpec.getKey(), "DESede");
		Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		cipher.init(Cipher.DECRYPT_MODE, desKey, ivSpec);
		return cipher.doFinal(encrypted);
	}

	private static byte[] base64Decode(String input) {

		final int invCodes[] = { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
				-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
				52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, 64, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
				11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30,
				31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1,
				-1 };
		if (input.length() % 4 != 0) {
			throw new IllegalArgumentException("Invalid base64 input");
		}
		byte decoded[] = new byte[((input.length() * 3) / 4)
				- (input.indexOf('=') > 0 ? (input.length() - input.indexOf('=')) : 0)];
		char[] inChars = input.toCharArray();
		int j = 0;
		int b[] = new int[4];
		for (int i = 0; i < inChars.length; i += 4) {
			b[0] = invCodes[inChars[i]];
			b[1] = invCodes[inChars[i + 1]];
			b[2] = invCodes[inChars[i + 2]];
			b[3] = invCodes[inChars[i + 3]];
			decoded[j++] = (byte) ((b[0] << 2) | (b[1] >> 4));
			if (b[2] < 64) {
				decoded[j++] = (byte) ((b[1] << 4) | (b[2] >> 2));
				if (b[3] < 64) {
					decoded[j++] = (byte) ((b[2] << 6) | b[3]);
				}
			}
		}

		return decoded;
	}
	
	static void close(Closeable cl) {
		if (cl != null) {
			try {
				cl.close();
			} catch (Exception e) {

			}
		}
	}

	public static String getJSONResponse(HttpEntity result ) throws JsonSyntaxException, ParseException, IOException {
		
		JsonParser parser = new JsonParser();
		JsonObject json = parser.parse(EntityUtils.toString(result)).getAsJsonObject();

		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		return gson.toJson(json);
	}

}
