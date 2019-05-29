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

import static org.jose4j.jws.AlgorithmIdentifiers.NONE;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.log4j.Logger;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.lang.StringUtil;
import org.jose4j.zip.CompressionAlgorithm;
import org.jose4j.zip.CompressionAlgorithmIdentifiers;
import org.jose4j.zip.DeflateRFC1951CompressionAlgorithm;

import eu.mf2c.security.ac.data.JsonJWE;
import eu.mf2c.security.ac.data.Recipient;
import eu.mf2c.security.ac.exception.MsgTokenBuilderException;
import eu.mf2c.security.ac.utility.AgentSingleton;
import eu.mf2c.security.ac.utility.Security;
import eu.mf2c.security.ac.utility.Type;

/**
 * Use this to build the appropriate type of message token. 
 * <p>
 * author Shirley Crompton
 * email  shirley.crompton@stfc.ac.uk
 * org Data Science and Technology Group,
 *      UKRI Science and Technology Council
 * Created 8 Mar 2019
 */
public class MsgTokenBuilder {
	/** Message logger */
	protected Logger LOGGER = Logger.getLogger(MsgTokenBuilder.class);
	/** Security policy for token */
	protected Security sec = null;
	/** Token type attribute */
	protected Type typ = null;
	/** library version */
	protected String vers = "1.0";
	/** payload compression flag, default is false **/
	protected boolean enableCompression = false;
	/** message payload */
	protected String payload = null;
	/** Recipients */
	protected List<String> recipients = new ArrayList<String>();	
	/** Credential helpder */
	protected AgentSingleton helper = AgentSingleton.getInstance();
	
	/**
	 * Default constructor
	 */
	public MsgTokenBuilder() {
		super();
	}
	/**
	 * Set recipients.
	 * <p>
	 * @param recipients one or more recipient device IDs.
	 * @return the same {@link MsgTokenBuilder <em>MsgTokenBuilder</em>} object.
	 * @throws IllegalArgumentException if no recipient is provided 
	 */
	public MsgTokenBuilder setRecipients(String... recipients) throws IllegalArgumentException {
		if(recipients == null || recipients.length == 0) {
			//shouldn't have set it at all
			throw new IllegalArgumentException("no recipient!");
		}else {
			this.recipients = Arrays.asList(recipients);
		}		
		return this;
	}
	
	/**
	 * Set the {@link eu.mf2c.security.ac.utility.Security <em>Security</em>} policy applicable.
	 * The policy determines what sort of token would be returned&#58;
	 * <ul>
	 * <li>public &#58; a token that is neither signed nor encrypted</li>
	 * <li>protected &#58; a token that is signed with the private key of the sender</li>
	 * <li>private &#58; a token with a payload that is encrypted using an AEAD algorithm
	 * &#40;AES&#45;GSM 256&#41; and a generated symmetric key.  The symmetric key is encrypted
	 * per recipient with the recipient&#39;s public key.  Additional associated data is integrity
	 * protected as part of the protected header.</li>
	 * </ul>
	 * <p>
	 * @param sec  the security policy to apply to the token
	 * @return the same {@link MsgTokenBuilder <em>MsgTokenBuilder</em>} object.
	 */
	public MsgTokenBuilder setSecPolicy(Security sec) {
		//
		this.sec = sec;		
		return this;
	}
	
	public MsgTokenBuilder setTyp(Type typ) {
		//
		this.typ = typ;		
		return this;
	}
	/**
	 * Set the payload compression flag
	 * <p>
	 * @param compFlag  enable payload compression if fag is set to true, default is false.
	 * @return the same {@link MsgTokenBuilder <em>MsgTokenBuilder</em>} object.
	 */
	public MsgTokenBuilder setEnableCompression(boolean compFlag) {
		this.enableCompression = compFlag;
		return this;
	}
	/**
	 * Set the payload content
	 * <p>
	 * @param payload  the content {@link java.lang.String <em>String</em>} 
	 * @return	the same {@link MsgTokenBuilder <em>MsgTokenBuilder</em>} object.
	 */
	public MsgTokenBuilder setMsgPayload(String payload) {
		this.payload = payload;
		return this;
	}
	
	
	
	/**
	 * Build the required message token as per the security policy. The recipients and 
	 * security policy are mandatory attributes that must be set before calling the build method.
	 * Also do not reuse the builder to build a different token as the attributes would not
	 * have been reinitialised.
	 * <p>
	 * @return the token string
	 * @throws MsgTokenBuilderException if there is an error
	 */
	public String build() throws MsgTokenBuilderException {
		//added typ 22 May 2019
		if(this.typ == null) {
			throw new MsgTokenBuilderException("No token type defined!");
		}
		if(this.typ != Type.JWT) {
			//all tokens except JWT must have security policy and payload
			if(this.sec == null){
				throw new MsgTokenBuilderException("No security policy defined!");
			}
			if(this.payload == null || this.payload.isEmpty()) {
				throw new MsgTokenBuilderException("No payload content!");
			}	
		}
		//private messages and JWT must have recipients as we need their public keys/dids
		if(this.recipients.isEmpty()) {
			if(this.sec.equals(Security.PRIVATE) || this.typ.equals(Type.JWT))  {
				throw new MsgTokenBuilderException("No recipients defined!");
			}
		}
		//System.out.println("Initialised: " + AgentSingleton.initialised);
		LOGGER.debug("Is AgentSingleton Initialised: " + AgentSingleton.initialised);
		
		if(!AgentSingleton.initialised) {
			AgentSingleton.initialise();
		}
		if(!AgentSingleton.initialised) {
			throw new MsgTokenBuilderException("Unable to initialise AgentSingleton!  Cannot proceed!");
		}
		//OK, proceed
		String tokenString = null;		
		//determine what to build JWT, JWS, JWE-single/multi recipients (use typ 22 May 2019)
		if(this.typ.equals(Type.PLAIN)) {
			LOGGER.debug("build unsigned JWS.....");
			tokenString = this.buildPlainToken();	
		}else if(this.typ.equals(Type.JWS)) {
			LOGGER.debug("build JWS.....");
			tokenString = this.buildJWS();
		}else if(this.typ.equals(Type.JWT)) {
			LOGGER.debug("build JWT.....");
			tokenString = this.buildJWT();
		}else {
			LOGGER.debug("build JWE for " + this.recipients);
			 tokenString = this.buildJWE();
		}
		/*
		if(sec.equals(Security.PUBLIC)) {
			LOGGER.debug("build unsigned JWS.....");
			tokenString = this.buildPlainToken();	
		}else if(sec.equals(Security.PROTECTED)) {
			LOGGER.debug("build JWS.....");
			tokenString = this.buildJWS();
		}else {
			LOGGER.debug("build JWE for " + this.recipients);
			 tokenString = this.buildJWE();
		}*/
		if(tokenString == null) {
			throw new MsgTokenBuilderException("Failed to build the token!");
		}
		return tokenString;
	}
	/**
	 * Build an unsigned JWS object to wrap the payload for a unprotected message.
	 * <p>
	 * @return	a {@link java.lang.String <em>String</em>} representation of the
	 * 			token
	 * @throws MsgTokenBuilderException on error
	 */
	private String buildPlainToken() throws MsgTokenBuilderException {
		LOGGER.debug("About to  build a plain token....");
		//A plan message token is a JWS that is not signed		
		String tokenstr = null;
        final JsonWebSignature jws = new JsonWebSignature();
        try {
        	 
        	//set payload, need to check if compression is needed
        	if(this.enableCompression) {
        		//set the zip header element
                jws.setHeader(HeaderParameterNames.ZIP, CompressionAlgorithmIdentifiers.DEFLATE);
                //and compress the plaintext payload
                byte[] compressed = compress();
                System.out.println("Unsigned JWS payload compressed length: " + compressed.length);
                LOGGER.debug("Unsigned JWS payload compressed length: " + compressed.length);
    			jws.setPayloadBytes(compressed); 
        	}else {
        		jws.setPayload(this.payload);
        	}
			//jws.setContentTypeHeaderValue("jws"); //should really set this, as the payload is plain text
			//set allowed algorithms so we can have an empty signature data object
        	jws.setAlgorithmConstraints(AlgorithmConstraints.ALLOW_ONLY_NONE);
			jws.setAlgorithmHeaderValue(NONE);; //flag unsecured JWS alg:none
			//jws.setAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS);
			jws.setHeader("typ", "JOSE"); // compact serialisation
			jws.setHeader("mf2c-sec",this.sec.toString().toLowerCase()); //so it is an unsigned JWS
			jws.setHeader("mf2c-tmsp", String.valueOf(Instant.now().toEpochMilli()));
			jws.setHeader("mf2c-sender", AgentSingleton.getInstance().getDid());
			jws.setHeader("mf2c-aclib", this.vers);
			//System.out.println("headers: " + jws.getHeaders().getFullHeaderAsJsonString());
			tokenstr = jws.getCompactSerialization();
			//System.out.println("tokenstr: \n" + tokenstr);
			if(tokenstr == null || tokenstr.isEmpty()) {;
				throw new MsgTokenBuilderException("Got null of empty unsigned JWS token string!");
			}
        } catch (Exception e) {
			LOGGER.error("Error creating unsigned JWS: " + e.getMessage());
			throw new MsgTokenBuilderException(e);
		}		
		return tokenstr;		
	}
	/**
	 * Compress the payload data using the RFC 1951 compression algorithm.
	 * <p>
	 * @return a byte array representation of the compressed payload
	 */
	private byte[] compress() {
		//note that JOSE4j JWE handles compression directly 
		byte[] data = StringUtil.getBytesUtf8(this.payload);
		CompressionAlgorithm ca = new DeflateRFC1951CompressionAlgorithm();
		return ca.compress(data);
	}
	/**
	 * Create a signed JWS message token for a protected message.  The token is signed using the private key
	 * associated with the sending agent&#39; x.509 certificate. The signature 
	 * is calculated over the base64url encoded header and the base64url encoded 
	 * payload, separated by a &#34;.&#34;
	 * <p>
	 * @return a {@link java.lang.String <em>String</em>} representation of the
	 * 			token
	 * @throws MsgTokenBuilderException on error
	 */
	private String buildJWS() throws MsgTokenBuilderException {
		LOGGER.debug("About to  build a JWS....");
		//
		String tokenStr = null;
		//
		try {
			//populate the token 
			final JsonWebSignature jws = new JsonWebSignature();
			// if compression, we need to set the zip header element
			if (this.enableCompression) {
				jws.setHeader(HeaderParameterNames.ZIP, CompressionAlgorithmIdentifiers.DEFLATE);
				// and compress the plaintext payload				
				byte[] compressed = compress();
				LOGGER.debug("Signed JWS compressed length: " + compressed.length);
				jws.setPayloadBytes(compressed);
			} else {
				jws.setPayload(this.payload);
			}			
			jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
			// jws.setContentTypeHeaderValue("jws"); //this is the nested token structure
			jws.setKey(AgentSingleton.getInstance().getJwk().getPrivateKey()); // for signing
			jws.setKeyIdHeaderValue(AgentSingleton.getInstance().getJwk().getKeyId());
			jws.setHeader("typ", "JOSE"); // compact serialisation
			jws.setHeader("mf2c-sec", this.sec.toString().toLowerCase()); // so it is an unsigned JWS
			jws.setHeader("mf2c-tmsp", String.valueOf(Instant.now().toEpochMilli()));
			jws.setHeader("mf2c-sender", AgentSingleton.getInstance().getDid());
			jws.setHeader("mf2c-aclib", this.vers);
			//Headers h = jws.getHeaders();
			//System.out.println("headers: " + h.getFullHeaderAsJsonString());
			tokenStr = jws.getCompactSerialization(); // this include signing if algorithm is set
			//
			if(tokenStr == null || tokenStr.isEmpty()) {
				//System.out.println("Got null of empty JWS token string!");
				throw new MsgTokenBuilderException("Got null of empty JWS token string!");
			}
			//System.out.println("tokenstr: \n" + tokenStr);			
			LOGGER.debug("tokenstr: \n" + tokenStr);
			//
		}catch (Exception e) {
			LOGGER.error("Error creating JWS: " + e.getMessage());
			throw new MsgTokenBuilderException(e);
		}		
		return tokenStr;
	}
	/**
	 * Build a JWE with an integrity protected header for a private message.
	 * An AEAD algorithm &#40;AES&#45;CBC&#45;Hmac;&#41; is used in an 
	 * encrypt&#45;then&#45;MAC approach to encrypt the plain text payload 
	 * using the AES&#47;CBC&#47;PKCS5Padding algorithm and a MAC is computed over the 
	 * ciphertext, initialization vector, additional associated data using 
	 * the SHA2 algorithm.
	 * <p>
	 * @return	a {@link java.lang.String <em>String</em>} representation of the JWE
	 * @throws MsgTokenBuilderException	on error
	 */
	private String buildJWE() throws MsgTokenBuilderException {
		LOGGER.debug("About to  build a JWE....");
		//first check if we are building a compact serialisation or a Json serialisation token
		String tokenString = null;
		//
		try {
			if(this.recipients.size()>1) {
				tokenString = this.buildJsonJWE();
			}else {
				tokenString = this.buildCompactJWE();
			}
			if(tokenString == null || tokenString.isEmpty()) {
				throw new MsgTokenBuilderException("JWE token string is null/empty!");
			}
		} catch (Exception e) {
			System.out.println("Error building JWE: " + e.getMessage());
			throw new MsgTokenBuilderException(e);
		}
		return tokenString;
	}
	/**
	 * Build a JWE intended for multiple recipients. The JWE has a 
	 * pert&#45;recipient header and is serialised as a generalised
	 * Json structure.
	 * <p> 
	 * @return	a {@link java.lang.String <em>String</em>} representation of the JWE
	 * @throws MsgTokenBuilderException 	on error
	 */
	String buildJsonJWE() throws MsgTokenBuilderException {
		LOGGER.debug("About to  build a Json JWE....");
		//there are more than 1 recipient, we will build a proper JSON structure
			String jweString = null;
			try {
				//get all the recipients' public keys
				List<Recipient> targets = new ArrayList<Recipient>();
				this.recipients.forEach(r->{
					targets.add(new Recipient(r));	//we get illegalStateEx if can't get r's key
				});
				LOGGER.debug("Got " + targets.size() + " recipient objects for " + this.recipients.size() + " recipients...");
				//
				JsonJWE jjwe = new JsonJWE(targets);
				//prepare the header
				jjwe.setHeader("mf2c-aclib", this.vers);
				//zip needs to be in the protected header
				if(this.enableCompression == true) {
					jjwe.setHeader(HeaderParameterNames.ZIP, CompressionAlgorithmIdentifiers.DEFLATE);
				}
				jjwe.setPayload(this.payload);
				jweString = jjwe.getJsonSerialisation();				
				//
				if(jweString == null || jweString.isEmpty()) {
					throw new MsgTokenBuilderException("jweString is null or empty!");
				}			
			} catch (Exception e) {
				throw new MsgTokenBuilderException("Failed to build the compact token: " + e.getMessage());
			}
			return jweString;	
	}
	/**
	 * Build a JWE intended for a single recipient.  The JWE has compact 
	 * serialisation format with five parts separated by a 	&#39;.&#39;
	 * <p>
	 * @return 	a {@link java.lang.String <em>String</em>} representation of the JWE
	 * @throws MsgTokenBuilderException	on error
	 */
	private String buildCompactJWE() throws MsgTokenBuilderException {
		LOGGER.debug("About to  build a compact JWE....");
		//there is only 1 recipient, we will build a JWE with compact serialisation representation
		String jweString = null;
		try {
			//get the public key of the recipient
			Recipient target = new Recipient(this.recipients.get(0));
			// Create a new Json Web Encryption object
			JsonWebEncryption senderJwe = new JsonWebEncryption();
			//use this key wrapping algorithm 		
			senderJwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA1_5);
			// Set content encryption "enc" header, we only support AES_128_CBC_HMAC_SHA_256 
			//which is a composition of AES CBC and HMAC SHA2 that provides authenticated encryption.
			//128 bits key size is sufficient for most use cases
			senderJwe
					.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
			if(this.enableCompression == true) {
				//JOSE4j handles JWE compression itself using the zip header element as a flag
				senderJwe.setHeader(HeaderParameterNames.ZIP, CompressionAlgorithmIdentifiers.DEFLATE);
			}
			senderJwe.setPayload(this.payload);
			senderJwe.setKey(target.getJwk().getKey());//use this to encrypt the symmetric key
			senderJwe.setKeyIdHeaderValue(target.getJwk().getKeyId());
			senderJwe.setHeader("typ", "JOSE"); // compact serialisation
			senderJwe.setHeader("mf2c-sec", this.sec.toString().toLowerCase()); // so it is an unsigned JWS
			senderJwe.setHeader("mf2c-tmsp", String.valueOf(Instant.now().toEpochMilli()));
			senderJwe.setHeader("mf2c-sender", AgentSingleton.getInstance().getDid());
			senderJwe.setHeader("mf2c-aclib", this.vers);
			//build the token
			jweString = senderJwe.getCompactSerialization();
			//
			if(jweString == null || jweString.isEmpty()) {
				throw new MsgTokenBuilderException("jweString is null or empty!");
			}			
		} catch (Exception e) {
			throw new MsgTokenBuilderException("Failed to build the compact JWE: " + e.getMessage());
		}
		return jweString;	
	}
	
	//21May2019 Build IDToken to support agent authentication
	/**
	 * Build a signed JWT to assert the Agent&#39;s identity 
	 * to support inter&#45;Agent communication
	 * @return	a {@link java.lang.String <em>String</em>} representation of the JWT
	 * @throws MsgTokenBuilderException	on errors
	 */
	public String buildJWT() throws MsgTokenBuilderException {
		LOGGER.debug("About to  build a signed JWT....");
		String jwt = null;
		try {
			RsaJsonWebKey jwk = AgentSingleton.getInstance().getJwk(); //kid is a random UUID

			// Create the Claims, which will be the content of the JWT
			JwtClaims claims = new JwtClaims();
			// These are reserved attributes
			claims.setIssuer(AgentSingleton.getInstance().getDid()); // who creates the token and signs it
			claims.setAudience(recipients); // 
			claims.setExpirationTimeMinutesInTheFuture(10); // time when the token will expire (10 minutes from now)
			claims.setGeneratedJwtId(); // a unique identifier for the token
			claims.setIssuedAtToNow(); // when the token was issued/created (now)
			claims.setNotBeforeMinutesInThePast(2); // time before which the token is not yet valid (2 minutes ago)
			//System.out.println("about to instantiate JWS!");
			//
			// The JWT is a JWS with JSON claims as the payload.
			JsonWebSignature jws = new JsonWebSignature();
			// The payload of the JWS is JSON content of the JWT Claims
			jws.setPayload(claims.toJson());			
			jws.setHeader("typ", "JOSE"); // compact serialisation, we are not using a nested token
			jws.setHeader("mf2c-sec", Security.PROTECTED.toString().toLowerCase()); // A JWT is a signed JWS
			jws.setHeader("mf2c-tmsp", String.valueOf(Instant.now().toEpochMilli()));
			jws.setHeader("mf2c-sender", AgentSingleton.getInstance().getDid());
			jws.setHeader("mf2c-aclib", this.vers);
			//
			//System.out.println("about to sign JWT!");
			// The JWT is signed using the private key
			jws.setKey(jwk.getPrivateKey());
			// Set the Key ID (kid) header because it's just the polite thing to do.
			jws.setKeyIdHeaderValue(jwk.getKeyId());
			// Set the signature algorithm on the JWT/JWS that will integrity protect the
			// claims
			jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
			// Sign jws
			jwt = jws.getCompactSerialization();
			// 
			LOGGER.debug("JWT String: " + jwt);
			
		}catch(Exception e){
			throw new MsgTokenBuilderException("Failed to build the signed JWT: " + e.getMessage());
		}		
		return jwt;
	}
	
	
	

	/**
	 * @param args
	 
	public static void main(String[] args) {
		MsgTokenBuilder mtb = new MsgTokenBuilder();
		try {
			//mtb.setRecipients("them","us","who else").build(); //should throw exception
			mtb.setEnableCompression(true).setRecipients("me","you").setSecPolicy(Security.PRIVATE).build();
			mtb.setEnableCompression(false).setRecipients("him").setSecPolicy(Security.PROTECTED).build();
			mtb.setRecipients("them","us","who else").build(); //no exception as inherited the sec policy from the previous statement
		} catch (IllegalArgumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (MsgTokenBuilderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}*/

}
