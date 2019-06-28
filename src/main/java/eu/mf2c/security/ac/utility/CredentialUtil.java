/**
 * Copyright 2018-20 UKRI Science and Technology Facilities Council

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 *     http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License 
 * 
 * SSLTools&#58;
 * Copyright 2016 Mendix bv
 * License: GPL&#45;2&#43;
 * 
 */
package eu.mf2c.security.ac.utility;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.UUID;

import org.apache.log4j.Logger;
import org.jose4j.base64url.Base64;
import org.jose4j.base64url.SimplePEMEncoder;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.Use;
import org.jose4j.lang.JoseException;

/**
 * Utilties for working with credentials. Some methods are based on the @see
 * <a href="https://github.com/mendix/SSLTools.git">SSLTools</a>
 * <p>
 * author Shirley Crompton email shirley.crompton@stfc.ac.uk org Data Science
 * and Technology Group, UKRI Science and Technology Council Created 8 Mar 2019
 */
public class CredentialUtil {
	/** message logger */
	protected static Logger LOGGER = Logger.getLogger(CredentialUtil.class);

	/**
	 * Extract a RSA Private Key from a base64 encoded
	 * {@link java.lang.String <em>String</em>} representation of a PKCS&#35;1 key object
	 * 
	 * @param pkcs1	{@link java.lang.String <em>String</em>} representation of
	 *            the input key object
	 * @return the converted RSA private key
	 */
	public static PrivateKey loadPKCS1PrivateKey(String pkcs1) {
		//
		PrivateKey pk = null;
		//
		KeyFactory factory;
		try {
			pkcs1 = pkcs1.replace("-----BEGIN RSA PRIVATE KEY-----", "");
			pkcs1 = pkcs1.replace("-----END RSA PRIVATE KEY-----", "");
			pkcs1 = pkcs1.replaceAll("\\s", "");// get rid of single white spaces/
			factory = KeyFactory.getInstance("RSA");
			//System.out.println("\nabout to decode : " + pkcs1);
			LOGGER.debug("about to decode pcks1 String....");
			byte[] pkcs1b = Base64.decode(pkcs1);
			RSAPrivateCrtKeySpec keyspec = getRSAKeySpec(pkcs1b);
			System.out.println("\nabout to generate private key : " + keyspec.getPublicExponent());
			pk = factory.generatePrivate(keyspec);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException | IOException ke) {

		}
		return pk;
	}
	/**
	 * Extract a RSA Private Key from a base64 encoded
	 * {@link java.lang.String <em>String</em>} representation of a PKCS&#35;8 key object
	 * 
	 * @param pkcs8	{@link java.lang.String <em>String</em>} representation of
	 *            the input key object
	 * @return the converted RSA private key
	 */
	public static PrivateKey loadPKCS8PrivateKey(String pkcs8) {
		
		PrivateKey pk = null;
		//
		KeyFactory factory;
		try {
			pkcs8 = pkcs8.replace("-----BEGIN RSA PRIVATE KEY-----", "");
			pkcs8 = pkcs8.replace("-----END RSA PRIVATE KEY-----", "");
			pkcs8 = pkcs8.replaceAll("\\s", "");// get rid of single white spaces/
			factory = KeyFactory.getInstance("RSA");
			//System.out.println("\nabout to decode : " + pkcs8);
			LOGGER.debug("about to decode pcks8 String....");
			//need to use a different decoder
			PKCS8EncodedKeySpec privKeySpec =
					new PKCS8EncodedKeySpec(SimplePEMEncoder.decode(pkcs8));
			pk = factory.generatePrivate(privKeySpec);
			//System.out.println("format: " + key.getFormat());
			//System.out.println("algorithm: " + key.getAlgorithm());
		} catch (InvalidKeySpecException | NoSuchAlgorithmException  ke) {
			//System.out.println("Error reading PKCS8 private key from PEM file! " + ke.getMessage());
			LOGGER.error("Error reading PKCS8 private key from PEM file! " + ke.getMessage());
		}
		return pk;
	}

	/**
	 * Parse a PKCS&#35;1 byte array object into a RSA key specification.
	 * 
	 * @see <a href="https://github.com/mendix/SSLTools.git">SSLTools</a>
	 *      <p>
	 * @param keyBytes
	 *            the PCKS&#35;1 object
	 * @return A {@link java.security.spec.RSAPrivateCrtKeySpec
	 *         <em>RSAPrivateCrtKeySpec</em>} object
	 * @throws IOException
	 *             on error parsing the key object.
	 */
	public static RSAPrivateCrtKeySpec getRSAKeySpec(byte[] keyBytes) throws IOException {
		//
		DerParser parser = new DerParser(keyBytes);
		Asn1Object sequence = parser.read();
		if (sequence.getType() != DerParser.SEQUENCE)
			throw new IOException("Invalid DER: not a sequence"); //$NON-NLS-1$
		// Parse inside the sequence
		parser = sequence.getParser();
		parser.read(); // Skip version
		BigInteger modulus = parser.read().getInteger();
		BigInteger publicExp = parser.read().getInteger();
		BigInteger privateExp = parser.read().getInteger();
		BigInteger prime1 = parser.read().getInteger();
		BigInteger prime2 = parser.read().getInteger();
		BigInteger exp1 = parser.read().getInteger();
		BigInteger exp2 = parser.read().getInteger();
		BigInteger crtCoef = parser.read().getInteger();
		//
		RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, prime1, prime2, exp1,
				exp2, crtCoef);
		//
		return keySpec;
	}
	/**
	 * Load the agent&#39;s certificate from the shared pki volume
	 * <p>	
	 * @param path  {@link java.lang.String <em>String</em>} representation of the file path 
	 * @return	the retrieved {@link java.security.cert.X509Certificate <em>X509Certificate</em>} 
	 * 			object or null if in error
	 */
	public static X509Certificate loadX509(String path) {
		X509Certificate certificate = null;
		try {
			FileInputStream fis = new FileInputStream(path);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			certificate = (X509Certificate) cf.generateCertificate(fis);
			// System.out.println("Type : " + certificate.getType());
			// System.out.println("Issuer Principal Name : " +
			// certificate.getIssuerX500Principal().getName());
			// System.out.println("Principal Name : " +
			// certificate.getSubjectX500Principal().toString());
			LOGGER.debug("Principal Name : " + certificate.getSubjectX500Principal().toString());
		} catch (Exception e) {
			//
			LOGGER.error("Error loading the certificate: " + e.getMessage());
		}
		return certificate;
	}
	/**
	 * Generate a RSA Json web key using the Agent&#39;s existing 2048 bits RSA public and private keys.
	 * The keys are associated with the Agent&#39;s X.509 certificate.  The process assigns a random
	 * UUID as the key id and set key use to allow signature and encryption.
	 * <p>
	 * @param pubK	RSA 2048 bit Public key
	 * @param privK	RSA 2048 bit Private key
	 * @return the generated RSA Json web key.
	 * @throws JoseException on error
	 */
	public static RsaJsonWebKey getJWK(PublicKey pubK, PrivateKey privK) throws JoseException {
		//
		RsaJsonWebKey rsaJwk =  (RsaJsonWebKey) PublicJsonWebKey.Factory.newPublicJwk(pubK);
        rsaJwk.setPrivateKey(privK);
        rsaJwk.setUse(Use.ENCRYPTION); //encryption includes signature use but not vice versa
        rsaJwk.setKeyId(UUID.randomUUID().toString());
		//
		return rsaJwk;
	}
	/**
	 * Generate a 2048 bit RSA {@link java.security.KeyPair <em>KeyPair</em>}.
	 * <p>
	 * @return the {@link java.security.KeyPair <em>KeyPair</em>} or null if error
	 */
	public static KeyPair generateKP() {
		KeyPairGenerator keyGen;
		KeyPair keypair = null;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(2048, new SecureRandom());
			keypair = keyGen.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			LOGGER.error("Error generating RSA keypair: " + e.getMessage());			
		} 
		return keypair;
	}

	/**
	 * @param args
	 * 
	 *            public static void main(String[] args) { // TODO Auto-generated
	 *            method stub
	 * 
	 *            }
	 */

}
