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
 */
package eu.mf2c.security.ac;

import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.jose4j.base64url.Base64Url;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwa.AlgorithmFactory;
import org.jose4j.jwa.AlgorithmFactoryFactory;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.jwx.CompactSerializer;
import org.jose4j.jwx.Headers;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.JsonHelp;
import org.jose4j.lang.StringUtil;
import org.jose4j.zip.CompressionAlgorithm;
import org.jose4j.zip.CompressionAlgorithmIdentifiers;

import eu.mf2c.security.ac.data.Sender;
import eu.mf2c.security.ac.exception.MsgTokenBuilderException;
import eu.mf2c.security.ac.exception.MsgTokenReaderException;
import eu.mf2c.security.ac.utility.AgentSingleton;
import eu.mf2c.security.ac.utility.Security;
import eu.mf2c.security.ac.utility.Type;

/**
 * A general purpose consumer that takes in a {@link java.lang.String
 * <em>String</em>} representation of a message token, unpacks it in line with
 * the specified {@link eu.mf2c.security.ac.utility.Security <em>Security</em>}
 * policy to extract the payload message.
 * <p>
 * author Shirley Crompton email shirley.crompton@stfc.ac.uk org Data Science
 * and Technology Group, UKRI Science and Technology Council Created 21 Mar 2019
 */
public class MsgTokenReader {
	/** Message Logger */
	protected Logger LOGGER = Logger.getLogger(MsgTokenReader.class);
	/** Msg Token String */
	private String tokenStr;
	/** Token type attribute */
	protected Type typ = null;
	/** library version */
	protected static String vers = "1.0";
	/**
	 * Constructor
	 * @param token	the token String to process
	 * @param typ	the token type
	 * @throws IllegalArgumentException	if null or an empty String is received
	 */
	public MsgTokenReader(String token, Type typ) throws IllegalArgumentException {
		if (token == null || token.isEmpty()) {
			throw new IllegalArgumentException("Null//empty msg token string, cannot proceed!");
		}
		if (typ == null ) {
			throw new IllegalArgumentException("token type must be defined!");
		}
		this.tokenStr = token;
		this.typ = typ;
	}
	/**
	 * Get the payload message from the plain, JWS and JWE tokens or validate claims for signed
	 * JWT token.  For signed JWS, JWT and JWE, the integrity of the 
	 * token is verified before can be extracted.
	 * <p>
	 * @return the plaintext payload or OK for JWT if operation is successful
	 * @throws MsgTokenReaderException	on processing errors
	 */
	public String handleToken() throws MsgTokenReaderException {
		//use type to determine token type 22 May 2019
		String msg = null;
		// determine what sort of token this is
		//if (this.tokenStr.startsWith("{\"protected")) {
		switch(this.typ) {
			case JWE : msg = handleJWE(); break;
			case JWS : msg = handleJWS(); break;
			case JWT : msg = handleJWT(); break;
			case PLAIN : msg = handleUnsignedJWS(); break;
		}		
		/** The unwrapping key error is hidden in JOSE4j, the actual thrown error is Tag authen error
		System.out.println("Error reading token: " + e.getMessage());
		if(e.getMessage().contains("Unwrapping failed at ")) {
			System.out.println("Unwrapping failed ! " );
		} 
		Throwable[] ts = e.getSuppressed();
		System.out.println("Ts length : " + ts.length); = 0!
		for(Throwable t : ts) {
			System.out.println("t : " + t.getClass().getName());
			if(t instanceof InvalidKeyException){
				System.out.println("caught invalid key exception");
			}
		}*/
		if(msg == null) {
			throw new MsgTokenReaderException("Failed to process the token!  Unknown error!");
		}
		return msg;
	}

	/**
	 * Perform preliminary check to see if we can work with the token. We check if
	 * the security library version is supported and if the token type is correct
	 * for the specified mf2c policy
	 * <p>
	 * 
	 * @param headers
	 *            a {@link java.lang.String <em>String</em>} of the header object
	 * @param type
	 *            token type, it needs to be one of&#58;
	 *            <ul>
	 *            <li>ujws &#58; unsigned for a public message</li>
	 *            <li>jws &#58; signed for a protected message</li>
	 *            <li>jwe &#58; encrypted for a private message</li>
	 *            </ul>
	 * @return true if supported, else false
	 * @throws MsgTokenReaderException
	 *             on error extracting the library version
	 */
	public boolean isPrevetted(String headers, String type) throws MsgTokenReaderException { // check the lib version
		String headerStr = Base64Url.decodeToUtf8String(headers); // headers is the aad
		Headers h = new Headers();
		try {
			h.setFullHeaderAsJsonString(headerStr);
			if (!h.getStringHeaderValue("mf2c-aclib").equals(this.vers)) {
				return false; // version not compatible. We only got one version
			}
			String policy = h.getStringHeaderValue("mf2c-sec");
			if (policy.equals(Security.PRIVATE.toString().toLowerCase()) && type.equals("jwe")) {
				return true;
			}
			if (policy.equals(Security.PROTECTED.toString().toLowerCase()) && type.equals("jws")) {
				return true;
			}
			if (policy.equals(Security.PUBLIC.toString().toLowerCase()) && type.equals("ujws")) {
				return true;
			}
		} catch (Exception e) {
			throw new MsgTokenReaderException(e);
		}
		return false;
		/**
		 * for all other conditions } Not sure if we should check the policy, what is
		 * someone changed the policy to deliberately create a mismatch?
		 **/
	}

	/**
	 * Perform a preliminary check to see if the ac library version is supported.
	 * <p>
	 * 
	 * @param encHeaders
	 *            a {@link java.lang.String <em>String</em>} representation of the header object
	 * @return true if supported, else false
	 * @throws MsgTokenReaderException
	 *             on error extracting the version header element
	 */
	public static boolean isSupported(String encHeaders) throws MsgTokenReaderException {
		// check the lib version
		String headerStr = Base64Url.decodeToUtf8String(encHeaders); // headers is the aad
		Headers h = new Headers();
		try {
			h.setFullHeaderAsJsonString(headerStr);
			if (h.getStringHeaderValue("mf2c-aclib").equals(vers)) {
				return true; // version not compatible. We only got one version
			} else {
				return false;
			}
		} catch (Exception e) {
			throw new MsgTokenReaderException(e);
		}
	}

	/**
	 * Decompress the payload using the RFC1951 compression algorithm. Based on the
	 * JOSE4J code.
	 * <p>
	 * 
	 * @param data
	 *            the payload bytes
	 * @return the decompressed payload bytes
	 * @throws JoseException
	 *             on error
	 */
	public byte[] decompress(byte[] data) throws JoseException {
		AlgorithmFactoryFactory factoryFactory = AlgorithmFactoryFactory.getInstance();
		AlgorithmFactory<CompressionAlgorithm> zipAlgFactory = factoryFactory.getCompressionAlgorithmFactory();
		CompressionAlgorithm compressionAlgorithm = zipAlgFactory.getAlgorithm(CompressionAlgorithmIdentifiers.DEFLATE);
		LOGGER.debug("About to de-compress data .....");
		return compressionAlgorithm.decompress(data);
	}

	/**
	 * Check if the zip header element is set.
	 * <p>
	 * 
	 * @param headers
	 *            the JWS {@link org.jose4j.jwx.Headers <em>Headers</em>} object
	 * @return true if zip element is set, else false
	 */
	public boolean decompress(Headers headers) {
		//
		String hs = headers.getFullHeaderAsJsonString();
		LOGGER.debug("the jws headers: " + hs);
		if (hs.contains("zip")) {
			return true;
		} else {
			return false;
		}
	}
	/**
	 * Get a basic Json Web Encryption object.
	 * <p>
	 * @param compactSerialization	a {@link java.lang.String <em>String</em>}
	 * 			representation of the JOSE compact serialization JWE 
	 * @return	a {@link org.jose4j.jwe.JsonWebEncryption <em>JsonWebEncryption</em>} object
	 * @throws JoseException	on error
	 */
	public JsonWebEncryption getJWE(String compactSerialization) throws JoseException {
		
		JsonWebEncryption jwe = new JsonWebEncryption();
		//
		AlgorithmConstraints algConstraints = new AlgorithmConstraints(ConstraintType.WHITELIST,
				KeyManagementAlgorithmIdentifiers.RSA1_5); // use matching key wrapping algorithm
		jwe.setAlgorithmConstraints(algConstraints);
		AlgorithmConstraints encConstraints = new AlgorithmConstraints(ConstraintType.WHITELIST,
				ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
		jwe.setContentEncryptionAlgorithmConstraints(encConstraints);
		//
		jwe.setCompactSerialization(compactSerialization);

		return jwe;
	}
	/**
	 * Get the JWE encrypted key from the per&#45;recipient header object matching this
	 * Agent&#39;s device id against the key id element value.
	 * <p>
	 * @param rec	The per&#45;recipient header object
	 * @return		The encoded encrypted key if found, else null
	 */
	@SuppressWarnings("unchecked")
	public String getEncryptedKey(Object rec) {
		Map<String, Object> map = (Map<String, Object>) rec;
		//header is an Object which means it is a map			
		Map<String, Object> header = (Map<String, Object>) map.get("header");
		//encrypted key is a String	
		String key = (String) header.get("kid");
		if(key.equals(AgentSingleton.getInstance().getDid())) {
			LOGGER.debug("Found encrypted key for owner Agent!");
			return (String) map.get("encrypted_key");
		}else {
			return null;
		}		
	}
	/**
	 * Check if this Agent is a recipient of the multi&#45;recipient Json Web Token.
	 * <p>
	 * @return	true if Agent is listed as a recipient, else false
	 */
	public boolean isRecipient() {
		String exp = "\"kid\":\"" + AgentSingleton.getInstance().getDid() + "\"";
		LOGGER.debug("kid expression to look for : " + exp);
		if(this.tokenStr.contains(exp)) {
			return true;
		}else
			return false;		
	}
	/**
	 * Handle JWE, verify the authenticity and decrypt the payload.
	 * <p>
	 * @return	the plaintext payload
	 * @throws MsgTokenReaderException  on procesing errors, including verification and key errors.
	 */
	public String handleJWE() throws MsgTokenReaderException {
		String payload = null;
		try {
			if (this.tokenStr.startsWith("{\"protected")) { //multi-recipient
				//first check if this agent is a recipient
				if(!isRecipient()) {
					throw new Exception("Agent is not an intended recipient of this JJWE!");
				}
				/**
				 * same argument though, if someone just changed the lib version to stop us
				 * from reading the token 
				 
				if(!isSupported(jjwe.getEncodedHeaders())) { 
					throw new MsgTokenReaderException("Incompatible AC lib version. Cannot proceed"); 
				}*/
				Map<String, Object> params;
				params = JsonUtil.parseJson(this.tokenStr);
				String pHeaders = JsonHelp.getString(params, "protected");
				LOGGER.debug("protected : " + pHeaders);
				String iv = JsonHelp.getString(params, "iv");
				LOGGER.debug("iv : " + iv);
				String ciphertext = JsonHelp.getString(params,"ciphertext");
				LOGGER.debug("ciphertext : " + ciphertext);
				String tag = JsonHelp.getString(params,"tag");
				LOGGER.debug("tag : " + tag);
				//Extract the per-recipient headers
				@SuppressWarnings("unchecked")
				List<Object> recs = (List<Object>) params.get("recipients");
				String encrypted_key = null;
				for(Object r : recs) {
					encrypted_key = this.getEncryptedKey(r);
					if(encrypted_key != null) {
						break;
					}
				}
				if(encrypted_key == null) {
					throw new MsgTokenReaderException("JJWE: failed to find encrypted_key!");
				}
				String cs = CompactSerializer.serialize(pHeaders, encrypted_key, iv, ciphertext, tag);
				LOGGER.debug("created token string: " + (cs == null ? "null" : cs));
				//
				JsonWebEncryption jwe = this.getJWE(cs);
				jwe.setKey(AgentSingleton.getInstance().getJwk().getPrivateKey());
				//get payload, this includes the verification, JWE handles compression directly
				payload = jwe.getPayload();	
			}else {//compact serialisation for single recipient
				String[] parts = CompactSerializer.deserialize(this.tokenStr);				
				// must have 5 parts
				if(parts.length != JsonWebEncryption.COMPACT_SERIALIZATION_PARTS) {
					throw new Exception("Compact serailisation JWE must have 5 separate parts!"); 
				}
				JsonWebEncryption jwe = this.getJWE(this.tokenStr);
				// set management key to decrypt encrypted_key
				jwe.setKey(AgentSingleton.getInstance().getJwk().getPrivateKey());
				// get the encrypted payload, this handles the decompression and verifies 
				// the authentication tag. We get an integrity exception if the check fails
				payload = jwe.getPayload();
				// end single recipient JWE
			}
		}catch (Exception e) {
			throw new MsgTokenReaderException(e);
			//downstream check for org.jose4j.lang.IntegrityException
		}
		return payload;
	}
	/**
	 * Handle JWS, verify the signature and get the payload.
	 * <p>
	 * @return	the plaintext payload
	 * @throws MsgTokenReaderException  on processing and signature errors.
	 */
	public String handleJWS() throws MsgTokenReaderException {
		String payload = null;
		try {
			JsonWebSignature jws = new JsonWebSignature();
			jws.setAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.WHITELIST,
					AlgorithmIdentifiers.RSA_USING_SHA256));
			jws.setCompactSerialization(this.tokenStr);
			Sender sender = new Sender(jws.getHeaders().getStringHeaderValue("mf2c-sender"));
			jws.setKey(sender.getJwk().getKey());
			// Check the signature
			if (!jws.verifySignature()) {
				throw new Exception("Token signature is invalid!");
			}
			// OK, safe to go ahead and get payload
			if (this.decompress(jws.getHeaders())) {
				payload = StringUtil.newStringUtf8(this.decompress(jws.getPayloadBytes()));
			} else {
				payload = jws.getPayload();
			}	
		}catch (Exception e) {
			throw new MsgTokenReaderException(e);
			//downstream check for org.jose4j.lang.IntegrityException
		}
		return payload;
	}
	
	/**
	 * Handle unsigned JWS, get the payload message.
	 * <p>
	 * @return	the plaintext payload
	 * @throws MsgTokenReaderException  on processing errors.
	 */
	String handleUnsignedJWS() throws MsgTokenReaderException {
		String payload = null;
		JsonWebSignature jws = new JsonWebSignature();
		try {
			jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.NONE);// flag unsecured JWS alg:none
			jws.setAlgorithmConstraints(AlgorithmConstraints.ALLOW_ONLY_NONE);
			jws.setCompactSerialization(this.tokenStr);
			//
			if (this.decompress(jws.getHeaders())) {
				payload = StringUtil.newStringUtf8(this.decompress(jws.getPayloadBytes()));
			} else {
				payload = jws.getPayload();
			}
		}catch (Exception e) {
			throw new MsgTokenReaderException(e);
			//downstream check for org.jose4j.lang.IntegrityException
		}
		return payload;
	}
	/**
	 * Handle JWT, verify the signature and the JWT claims.
	 * <p>
	 * @return	OK if JWT claims are authenticated
	 * @throws MsgTokenReaderException  on processing and claims errors.
	 */
	String handleJWT() throws MsgTokenReaderException {
		String rc = null;
		try {
			// Build a JwtConsumer that doesn't check signatures or do any validation.
		    JwtConsumer firstPassJwtConsumer = new JwtConsumerBuilder()
		            .setSkipAllValidators()
		            .setDisableRequireSignature()
		            .setSkipSignatureVerification()
		            .build();
		    //The first JwtConsumer is basically just used to parse the JWT into a JwtContext object.
		    JwtContext jwtContext = firstPassJwtConsumer.process(this.tokenStr);
		    // Get the issuer to look up the key, this would be the issuing Agent's deviceID
		    String issuer = jwtContext.getJwtClaims().getIssuer();
			Sender sender = new Sender(issuer);
			//second pass JwtConsumer, authorisation is done by CIMI, we just to authenticate the ID
			//this JwtConsumer is set up to verify the signature and validate the claims.
			JwtConsumer jwtConsumer = new JwtConsumerBuilder().setRequireExpirationTime() 
					.setAllowedClockSkewInSeconds(30) // add some leeway in validating time based claims to account for
					// clock skew
					.setExpectedIssuer(issuer) // whom the JWT needs to have been issued by
					.setExpectedAudience(AgentSingleton.getInstance().getDid()) // get this Agent's deviceId
					.setVerificationKey(sender.getJwk().getKey()) // verify the signature with the public key
					.setJwsAlgorithmConstraints( // only allow the expected signature algorithm(s) in the given context
							new AlgorithmConstraints(ConstraintType.WHITELIST, // which is only RS256 here
									AlgorithmIdentifiers.RSA_USING_SHA256))
					.build(); // create the JwtConsumer instance		
			// Validate the JWT Claims, reuse the same context to avoid redundant parsing			
			jwtConsumer.processContext(jwtContext);
			LOGGER.debug("JWT validation succeeded! ");
			rc = "OK";
			//
		} catch (InvalidJwtException e) {
			// InvalidJwtException will be thrown, if the JWT failed processing or
			// validation in anyway.
			LOGGER.error("Invalid JWT! " + e);
			// Whether or not the JWT has expired being one common reason for invalidity
			if (e.hasExpired()) {
				try {
					throw new MsgTokenReaderException("JWT expired at " + e.getJwtContext().getJwtClaims().getExpirationTime());
				} catch (MalformedClaimException e1) {
					throw new MsgTokenReaderException("MalformedClaimsException encountered when processing claims expired error!");
				}
			}
			// Or maybe the audience was invalid
			if (e.hasErrorCode(ErrorCodes.AUDIENCE_INVALID)) {
				try {
					throw new MsgTokenReaderException("JWT had wrong audience: " + e.getJwtContext().getJwtClaims().getAudience());
				} catch (MalformedClaimException e1) {
					throw new MsgTokenReaderException("MalformedClaimsException encountered when processing wrong audience claim!");
				}
			}
			if (e.hasErrorCode(ErrorCodes.SIGNATURE_INVALID)) {
				throw new MsgTokenReaderException("JWT signature invalid!");
			}
		} catch(Exception e) {
			throw new MsgTokenReaderException(e);
		}//filtering of error done at the TCP requestHandler level
		return rc;
	}
	
	
	
	
	
	/**
	 * @param args
	 
	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}*/

}
