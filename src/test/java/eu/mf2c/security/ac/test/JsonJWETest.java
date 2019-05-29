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
package eu.mf2c.security.ac.test;

import static org.junit.Assert.fail;

import java.util.Map;
import java.util.UUID;

import org.apache.log4j.Logger;
import org.jose4j.base64url.Base64Url;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwx.Headers;
import org.jose4j.lang.JsonHelp;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import eu.mf2c.security.ac.MsgTokenBuilder;
import eu.mf2c.security.ac.MsgTokenReader;
import eu.mf2c.security.ac.utility.Security;
import eu.mf2c.security.ac.utility.Type;

/**
 * Tests for creating and decrypting a multi&#45;recipient JWE serialised in
 * general Json format.
 * <p>
 * author Shirley Crompton email shirley.crompton@stfc.ac.uk org Data Science
 * and Technology Group, UKRI Science and Technology Council Created 25 Mar 2019
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class JsonJWETest {
	/** Message Logger */
	protected static Logger LOGGER = org.apache.log4j.Logger.getLogger(JsonJWETest.class);
	/** JWS compact serialization String */
	public static String token;
	public static String message = "Well, as of this moment, they're on DOUBLE SECRET PROBATION! +"
			+ "Do you really care?  I don't. " + "The silver fox quickly jumped over the fence.  As long as it doesn't"
			+ " eat my chickens...." + "It can go as it pleases. :D";
	// this is the local Agent's did
	/** sender device id */
	public static String sender = "0f848d8fb78cbe5615507ef5a198f660ac89a3ae03b95e79d4ebfb3466c20d54e9a5d9b9c41f88c782d1f67b32231d31b4fada8d2f9dd31a4d884681b784ec5a";
	// get a random 128-bit long String as the recipient device id
	/** Array of recipient device ids */
	public static String[] dids;
	/** Base64 utils */
	public static Base64Url base64url;

	/**
	 * Set up before test class
	 * 
	 * @throws java.lang.Exception
	 *             on errors
	 */
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		dids = new String[3];
		for (int count = 0; count < 3; count++) {
			dids[count] = UUID.randomUUID().toString();
		}
		base64url = new Base64Url();
	}

	/**
	 * Clean up after test class
	 * 
	 * @throws java.lang.Exception
	 *             on errors
	 */
	@AfterClass
	public static void tearDownAfterClass() throws Exception {
		token = null;
		message = null;
		sender = null;
		dids = null;
		base64url = null;
	}

	/**
	 * Test building a compact JWE without payload compression
	 * and validate the claims directly
	 */
	@Test
	public void testABuildingJJWE_UC() {
		LOGGER.info("running testABuildingJJWE_UC....");

		MsgTokenBuilder mtb = new MsgTokenBuilder();

		try {
			// method either throw an exception or return the token string, no need to check
			token = mtb.setEnableCompression(false).setSecPolicy(Security.PRIVATE).setRecipients(dids)
					.setMsgPayload(message).setTyp(Type.valueOf("JWE")).build();
			//
			LOGGER.debug("The Json JWE:\n " + token);
			Map<String, Object> params;
			params = JsonUtil.parseJson(token);
			String pHeaders = JsonHelp.getString(params, "protected");
			String aad = base64url.base64UrlDecodeToUtf8String(pHeaders);
			LOGGER.debug("aad: " + aad);
			Map<String, Object> phMap = JsonUtil.parseJson(aad);
			//
			Assert.assertEquals("mf2c-sec should be private!", "private", phMap.get("mf2c-sec"));
			Assert.assertEquals("mf2c-sender is incorrect!", sender, phMap.get("mf2c-sender"));
			// mf2c-aclib
			Assert.assertEquals("mf2c-aclib is incorrect!", "1.0", phMap.get("mf2c-aclib"));
			Assert.assertEquals("typ is incorrect!", "json", phMap.get("typ"));
			//
		} catch (IllegalArgumentException e) {
			fail("Illegal Argument: " + e.getMessage());
		} catch (Exception e) {
			fail("Error test building a Json JWE w/o compression: " + e.getMessage());
		}
	}

	/**
	 * Test building a compact JWE with payload compression
	 */
	@Test
	public void testBBuildingJJWE() {
		LOGGER.info("running testBBuildingJJWE....");

		MsgTokenBuilder mtb = new MsgTokenBuilder();

		try {
			// method either throw an exception or return the token string, no need to check
			token = mtb.setEnableCompression(true).setSecPolicy(Security.PRIVATE).setRecipients(dids)
					.setMsgPayload(message).setTyp(Type.valueOf("JWE")).build();
			//
			Map<String, Object> params;
			params = JsonUtil.parseJson(token);
			String pHeaders = JsonHelp.getString(params, "protected");
			String aad = base64url.base64UrlDecodeToUtf8String(pHeaders);
			LOGGER.debug("aad: " + aad);
			Map<String, Object> phMap = JsonUtil.parseJson(aad);
			//
			Assert.assertEquals("Zip element should be defined!", "DEF", phMap.get("zip"));
			System.out.println("message: " + message.length() + " + ciphertext length: " + ((String) params.get("ciphertext")).length());
			///Assert.assertTrue("Compressed payload should be smaller!",((String) params.get("ciphertext")).length() < message.length());
			//
		} catch (IllegalArgumentException e) {
			fail("Illegal Argument: " + e.getMessage());
		} catch (Exception e) {
			fail("Error test building a Json JWE with compression: " + e.getMessage());
		}
	}

}
