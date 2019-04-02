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
package eu.mf2c.security.ac.data;

import java.security.Key;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.jose4j.base64url.Base64Url;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmFactory;
import org.jose4j.jwa.AlgorithmFactoryFactory;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwe.ContentEncryptionAlgorithm;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.ContentEncryptionKeyDescriptor;
import org.jose4j.jwe.ContentEncryptionKeys;
import org.jose4j.jwe.ContentEncryptionParts;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithm;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwx.CompactSerializer;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.Headers;
import org.jose4j.lang.InvalidAlgorithmException;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.JsonHelp;
import org.jose4j.lang.StringUtil;
import org.jose4j.zip.CompressionAlgorithm;

import eu.mf2c.security.ac.MsgTokenBuilder;
import eu.mf2c.security.ac.data.Recipient;
import eu.mf2c.security.ac.exception.JsonJWEException;
import eu.mf2c.security.ac.utility.AgentSingleton;
import eu.mf2c.security.ac.utility.Security;

/**
 * This class extends the JOSE4j {@link org.jose4j.jwe.JsonWebEncryption
 * <em>JsonWebEncryption</em>} class. It adds methods for building a
 * per&#45;recipient Json web encryption object with general Json serialisation.
 * The AEAD algorithm &#40;AES&#45;CBC&#45;Hmac;&#41; is used in an
 * encrypt&#45;then&#45;MAC approach to encrypt the plain text payload using the
 * AES&#47;CBC&#47;PKCS5Padding algorithm and a MAC is computed over the
 * ciphertext, initialization vector, additional associated data &#40;AAD&#41;
 * using the SHA2 algorithm. The key encryption key must be an RSA 2048 bit
 * public key. The AAD is stored as part of the protected header. If the
 * &#39;zip&#39; header element is defined, the plain text payload is compressed
 * using the RFC 1951 compression algorithm.
 * <p>
 * author Shirley Crompton email shirley.crompton@stfc.ac.uk org Data Science
 * and Technology Group, UKRI Science and Technology Council Created 20 Mar 2019
 * *
 */
public class JsonJWE extends org.jose4j.jwe.JsonWebEncryption {
	/** Message logger */
	protected Logger LOGGER = Logger.getLogger(MsgTokenBuilder.class);
	/** List of recipients */
	private List<Recipient> targets;
	/** base64url helper */
	private Base64Url base64url = new Base64Url();
	/** a Json JWE token String object */
	private String token;

	/**
	 * Construct an instant. This method is used for encrypting a JWE token.
	 * <p>
	 * 
	 * @param recs
	 *            The list of {@link eu.mf2c.security.ac.data.Recipient
	 *            <em>Recipient</em>}
	 */
	public JsonJWE(List<Recipient> recs) {
		this.targets = recs;
	}
	/**
	 * Default constructor.  Use this to create an instance 
	 * for decrypting a private message token
	 * <p>
	 * @param token		a {@link java.lang.String <em>String</em>} representation of the JWE
	 *         Json object
	 * @throws	IllegalArgumentException	if no token String is provided
	 */
	public JsonJWE(String token) throws IllegalArgumentException {
		if(token == null || token.isEmpty()) {
			throw new IllegalArgumentException("Null\\empty Json JWE token string!");
		}
		this.token = token;
		
	}
	/**
	 * Get the general Json serialisation of a multi&#45;recipient JWE.
	 * <p>
	 * 
	 * @return a {@link java.lang.String <em>String</em>} representation of the JWE
	 *         Json object
	 * @throws JsonJWEException
	 *             on error
	 */
	public String getJsonSerialisation() throws JsonJWEException {
		//
		String tokenStr = null;
		try {
			if (this.targets == null || this.targets.isEmpty()) {
				throw new JsonJWEException("There are no recipients!");
			}
			super.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA1_5); 
			super.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
			super.setHeader("typ", "json");
			super.setHeader("mf2c-sec", Security.PRIVATE.toString().toLowerCase());
			super.setHeader("mf2c-tmsp", String.valueOf(Instant.now().toEpochMilli()));
			super.setHeader("mf2c-sender", AgentSingleton.getInstance().getDid());
			// payload and header elements for lib version and zip to be set by caller
			KeyManagementAlgorithm keyManagementModeAlg = getKeyManagementModeAlgorithm();
			LOGGER.debug("keyManagementModeAlg: " + keyManagementModeAlg.getClass().getName());
			ContentEncryptionAlgorithm contentEncryptionAlg = getContentEncryptionAlgorithm();
			LOGGER.debug("contentEncryptionAlg: " + contentEncryptionAlg.getClass().getName());
			ContentEncryptionKeyDescriptor contentEncryptionKeyDesc = contentEncryptionAlg
					.getContentEncryptionKeyDescriptor();
			/**
			 * go through each recipient and get an encrypted key which is stored in the
			 * Recipient object
			 */
			for (Recipient target : this.targets) {
				this.encryptKey(target, keyManagementModeAlg, contentEncryptionKeyDesc, contentEncryptionAlg);
			}
			byte[] aad = this.getEncodedHeaderAsciiBytesForAAD();
			LOGGER.debug("aad: " + Base64Url.decodeToUtf8String(StringUtil.newStringUsAscii(aad)));
			// {"alg":"RSA1_5","enc":"A128CBC-HS256","typ":"json","mf2c-sec":"private","mf2c-tmsp":"1553008620322"}
			byte[] contentEncryptionKey = super.getContentEncryptionKey();
			byte[] plaintextBytes = super.getPlaintextBytes();
			if (plaintextBytes == null) {
				throw new NullPointerException("The plaintext payload for the JWE has not been set.");
			}
			// compress if required
			plaintextBytes = this.compressContent(getHeaders(), plaintextBytes);
			ContentEncryptionParts contentEncryptionParts = contentEncryptionAlg.encrypt(plaintextBytes, aad,
					contentEncryptionKey, super.getHeaders(), super.getIv(), super.getProviderCtx());
			// compile the Json object
			String protectedAAD = StringUtil.newString(aad, StringUtil.UTF_8);// already ASCII encoded
			// get per-recipient header object
			List<Map<String, Object>> recHeaders = this.getRecHeaders();
			String encodedCiphertext = base64url.base64UrlEncode(contentEncryptionParts.getCiphertext());
			String encodedIv = base64url.base64UrlEncode(contentEncryptionParts.getIv());
			String encodedTag = base64url.base64UrlEncode(contentEncryptionParts.getAuthenticationTag());
			Map<String, Object> topLevel = new LinkedHashMap<>(); // use LinkedHM to preserve order
			topLevel.put("protected", protectedAAD);
			topLevel.put("recipients", recHeaders);
			topLevel.put("iv", encodedIv);
			topLevel.put("ciphertext", encodedCiphertext);
			topLevel.put("tag", encodedTag);
			tokenStr = JsonUtil.toJson(topLevel);
			LOGGER.debug("The JSN token : \n" + tokenStr);
		} catch (Exception e) {
			throw new JsonJWEException(e);
		}
		return tokenStr;
	}

	/**
	 * Reconstruct the Json web encryption object from the provided
	 * {@link java.lang.String <em>String</em>} representation. The 
	 * integrity is validated first before the payload is decrypted.
	 * <p>
	 * @param token	a {@link java.lang.String <em>String</em>} representation of the JWE
	 *         Json object
	 * @return	the decrypted payload text
	 * @throws JsonJWEException	if the integrity check fails or there is a processing error
	 */
	public String decryptPayload(String token) throws JsonJWEException {
		String jweCompact = this.getCompactJWEString(token);
		if(jweCompact != null) {
			try {
				//create a stub JWE using the jwe String
				JsonWebEncryption jwe = new JsonWebEncryption();
				// Set the algorithm constraints based on what is agreed upon or expected from the sender
			    AlgorithmConstraints algConstraints = new AlgorithmConstraints(ConstraintType.WHITELIST, KeyManagementAlgorithmIdentifiers.RSA1_5);
			    jwe.setAlgorithmConstraints(algConstraints);
			    AlgorithmConstraints encConstraints = new AlgorithmConstraints(ConstraintType.WHITELIST, ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
			    jwe.setContentEncryptionAlgorithmConstraints(encConstraints);
			    //		
				jwe.setCompactSerialization(token);
				//set private key of recipient (to decrypt)
				jwe.setKey(AgentSingleton.getInstance().getJwk().getPrivateKey());
				//get payload, this includes the verification
				String payload = jwe.getPayload();
				if(payload == null || payload.isEmpty()) {
					throw new Exception("the decrypted payload is empty//null!");
				}else {
					LOGGER.debug("the payload: " + payload);
					return payload;
				}				
			} catch (Exception e) {
				throw new JsonJWEException(e);
			}
		}
		return null;
	}
	/**
	 * Extract and build a compact {@link java.lang.String <em>String</em>} 
	 * representation of a single recipient JWE.
	 * <p> 
	 * @param token	a {@link java.lang.String <em>String</em>} representation 
	 * 			of the original multi&#45;recipient JWE Json serialisation.
	 * @return	a {@link java.lang.String <em>String</em>} representation of a 
	 * 			compact JWE 
	 * @throws JsonJWEException	on processing error
	 */
	@SuppressWarnings("unchecked")
	public String getCompactJWEString(String token) throws JsonJWEException {
		Map<String, Object> params;
		try {
			//convert to a map
			params = JsonUtil.parseJson(token);
			String pHeaders = JsonHelp.getString(params, "protected");
			LOGGER.debug("extracted encoded protected headers : " + pHeaders);
			String iv = JsonHelp.getString(params, "iv");
			LOGGER.debug("extracted encoded iv : " + iv);
			String ciphertext = JsonHelp.getString(params,"ciphertext");
			LOGGER.debug("extracted encoded ciphertext : " + ciphertext);
			String tag = JsonHelp.getString(params,"tag");
			LOGGER.debug("extracted encoded tag : " + tag);
			//			
			List<Object> recs = (List<Object>) params.get("recipients");
			//now look for the encrypted key for the recipient
			String encryptedKey = null;
			String did = AgentSingleton.getInstance().getDid();
			for(Object rec : recs) {
				//cast per-recipient header object to a map
				Map<String, Object> map = (Map<String, Object>) rec;				
				Map<String, Object> header = (Map<String, Object>) map.get("header");
				String kid = (String) header.get("kid");
				if(kid.equals(did)) {
					encryptedKey = (String) map.get("encrypted_key");
					break; //no need to go further
				}
			}
			if(encryptedKey == null) {
				throw new JsonJWEException("failed to extract encrypted key for owner(" + did + ")");
			}			
			String cs = CompactSerializer.serialize(pHeaders, encryptedKey, iv, ciphertext, tag);
			LOGGER.debug("created token string: " + (cs == null ? "null" : cs));
			return cs;
			
		} catch (Exception e) {
			throw new JsonJWEException(e);
		}
	}	

	/**
	 * Create the per&#45;recipient header object.
	 * <p>
	 * @return the header as a list of map objects.
	 */
	private List<Map<String, Object>> getRecHeaders() {
		List<Map<String, Object>> recHeaders = new ArrayList<>();
		for (Recipient r : this.targets) {
			// encrypted_key is String:String
			// header is String:Hashmap
			Map<String, Object> rec = new LinkedHashMap<>();
			// use a linked hashmap to preserve ordering
			Map<String, String> headerMap = new LinkedHashMap<String, String>();
			headerMap.put("alg", "RSA1_5");
			headerMap.put("kid", r.getJwk().getKeyId());
			rec.put("header", headerMap);
			// rec.put("header", value);
			rec.put("encrypted_key", base64url.base64UrlEncode(r.getEncryptionKey()));
			recHeaders.add(rec);
			// debug
			rec.forEach((k, v) -> LOGGER.debug(k + " : " + v));
		}
		return recHeaders;
	}
	
	//////////////// override or replace JOSE4j JWE methods////////////////////////
	/**
	 * Compress the payload if the the &#39;zip&#39; header element is defined.
	 * Based on the JOSE4J code
	 * <p> 
	 * @param headers
	 *            the JWE header object
	 * @param data
	 *            the payload bytes
	 * @return the compressed payload bytes if compression is required.
	 * @throws InvalidAlgorithmException
	 *             if the specified compression algorithm is not supported
	 */
	private byte[] compressContent(Headers headers, byte[] data) throws InvalidAlgorithmException {
		String zipHeaderValue = headers.getStringHeaderValue(HeaderParameterNames.ZIP);
		if (zipHeaderValue != null) {
			LOGGER.debug("uncompressed data byte length: " + data.length);
			AlgorithmFactoryFactory factoryFactory = AlgorithmFactoryFactory.getInstance();
			AlgorithmFactory<CompressionAlgorithm> zipAlgFactory = factoryFactory.getCompressionAlgorithmFactory();
			CompressionAlgorithm compressionAlgorithm = zipAlgFactory.getAlgorithm(zipHeaderValue);
			data = compressionAlgorithm.compress(data);
			LOGGER.debug("Compressed data byte length: " + data.length);
		}
		return data;
	}
	//we use the JOSE4j jwe for decrypting a encrypted jwe, so it can use the native method

	/**
	 * Get an ASCII representation of the base64url encoded header {@link String
	 * <em>String</em>}
	 * <p>
	 * 
	 * @return the header in bytes
	 */
	private byte[] getEncodedHeaderAsciiBytesForAAD() {
		// RFC7516 defines the header as ASCII(Base64URL(UTF8(protectedHeader)))
		String encodedHeader = super.getEncodedHeader();
		return StringUtil.getBytesAscii(encodedHeader);
	}
	/**
	 * Retrieve the protected headers as a UTF8 String.  This method does not verify
	 * the integrity of the headers.
	 * <p>
	 * @return		a {@link java.lang.String <em>String</em>} representation of the protected headers
	 * @throws JsonJWEException	 on error
	 */
	public String getProtectedHeaders() throws JsonJWEException {
		//this method does not verify the integrity, just retrieve the String		
		try {
			return Base64Url.decodeToUtf8String(this.getEncodedHeaders());
		} catch (Exception e) {
			throw new JsonJWEException(e);
		}		
	}
	/**
	 * Retrieve the encoded protected headers as a String.  This method does not verify
	 * the integrity of the headers.
	 * <p>
	 * @return	a {@link java.lang.String <em>String</em>} representation of the encoded
	 * 			 protected headers
	 * @throws JsonJWEException	on error
	 */
	public String getEncodedHeaders() throws JsonJWEException {
		//this method does not verify the integrity, just retrieve the String
			Map<String, Object> params;
			try {
				params = JsonUtil.parseJson(this.token);
				String eHeaders = JsonHelp.getString(params, "protected");				
				if(eHeaders == null || eHeaders.isEmpty()) {
					throw new JsonJWEException("encoded protected headers are null//empty!");
				}else {
					//LOGGER.debug("aad: " + headers);
					return eHeaders;
				}			
			} catch (Exception e) {
				throw new JsonJWEException(e);
			}		
	}
	

	/**
	 * Get the encrypted&#95;key for each recipient. The recipient&#39;s key is
	 * validated by default against the key encryption algorithm for compatibility.
	 * The content encryption key &#40;CEK&#41; is generated if it does not exist.
	 * The existing CEK is used if it is available.
	 * <p>
	 * 
	 * @param target
	 *            the recipient
	 * @param keyManagementModeAlg
	 *            the key management mode
	 * @param contentEncryptionKeyDesc
	 *            the content encryption descriptor
	 * @param contentEncryptionAlg
	 *            the content encryption algorithm.
	 * @throws JoseException
	 *             on error
	 */
	private void encryptKey(Recipient target, KeyManagementAlgorithm keyManagementModeAlg,
			ContentEncryptionKeyDescriptor contentEncryptionKeyDesc, ContentEncryptionAlgorithm contentEncryptionAlg)
			throws JoseException {

		Key managementKey = target.getJwk().getKey();
		if (isDoKeyValidation()) {
			keyManagementModeAlg.validateEncryptionKey(managementKey, contentEncryptionAlg);
		}
		// the AES contentEncryptionKey initially is null and is generated randomly with
		// the call below
		// the ContentEncryptionKeys class hold the CEK and EK (the EK for each
		// recipient)
		ContentEncryptionKeys contentEncryptionKeys = keyManagementModeAlg.manageForEncrypt(managementKey,
				contentEncryptionKeyDesc, getHeaders(), super.getContentEncryptionKey(), getProviderCtx());
		// the call above also wrap the AES content encryption key using the
		// (recipient's) management key (this is the encrypted key)
		if (super.getContentEncryptionKey() == null) {
			// this should only be called once for the first recipient
			LOGGER.debug("Setting content encryption key for target(" + target.getJwk().getKeyId() + ")");
			super.setContentEncryptionKey(contentEncryptionKeys.getContentEncryptionKey());
		}
		// the per-recipient header is unprotected (not integrity protected)
		target.setEncryptionKey(contentEncryptionKeys.getEncryptedKey());
	}

}
