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

import java.util.UUID;

import org.apache.log4j.Logger;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.CompactSerializer;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import eu.mf2c.security.ac.MsgTokenBuilder;
import eu.mf2c.security.ac.MsgTokenReader;
import eu.mf2c.security.ac.utility.Security;
import eu.mf2c.security.ac.utility.Type;

/**
 * Test creating and reading compact JWE object
 * for a single recipient.
 * <p>
 * author Shirley Crompton
 * email  shirley.crompton@stfc.ac.uk
 * org Data Science and Technology Group,
 *      UKRI Science and Technology Council
 * Created 22 Mar 2019
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class CompactJWETest {
	/** Message Logger */
	protected static Logger LOGGER = org.apache.log4j.Logger.getLogger(CompactJWETest.class);
	/** JWS compact serialization String */
	public static String token;
	public static String message = "Well, as of this moment, they're on DOUBLE SECRET PROBATION! +"
			+ "Do you really care?  I don't. " + "The silver fox quickly jumped over the fence.  As long as it doesn't"
			+ " eat my chickens...." + "It can go as it pleases. :D";
	// this is the local Agent's did
	/** sender device id */
	public static String sender = "0f848d8fb78cbe5615507ef5a198f660ac89a3ae03b95e79d4ebfb3466c20d54e9a5d9b9c41f88c782d1f67b32231d31b4fada8d2f9dd31a4d884681b784ec5a";
	// get a random 128-bit long String as the recipient device id
	/** recipient device id */
	//public static String did = UUID.randomUUID().toString();
	//using real device id that cau has a public key for
	public static String did = "a123456789df20e2d2f81f87fe69bf0b7dd14f4a22cca5f15ffc645cb4d45944bfdc7a7a970a9e13a331161e304a3094d8e6e362e88bd7df0d7b5473b6d2aa80";
	
	/**
	 * Set up before test class
	 * @throws java.lang.Exception
	 *             on errors
	 */
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {

	}

	/**
	 * Clean up after test class
	 * @throws java.lang.Exception
	 *             on errors
	 */
	@AfterClass
	public static void tearDownAfterClass() throws Exception {
		token = null;
		message = null;
		sender = null;
		did = null;
	}
	/**
	 * Test building a compact JWE without payload compression
	 */
	@Test
	public void testBuildingJWE_UC() {
		LOGGER.info("running testBuildingJWE_UC....");

		MsgTokenBuilder mtb = new MsgTokenBuilder();		

		try {
			// method either throw an exception or return the token string, no need to check
			token = mtb.setTyp(Type.JWE).setEnableCompression(false).setSecPolicy(Security.PRIVATE).setRecipients(did).setMsgPayload(message).build();
			LOGGER.debug("JWE token :\n" + token);
			//
			String[] jwsA = CompactSerializer.deserialize(token);
			Assert.assertTrue(jwsA.length == 5);
			//
			JsonWebEncryption jwe = new JsonWebEncryption();
			AlgorithmConstraints algConstraints = new AlgorithmConstraints(ConstraintType.WHITELIST,
					KeyManagementAlgorithmIdentifiers.RSA1_5); // use matching key wrapping algorithm
			jwe.setAlgorithmConstraints(algConstraints);
			AlgorithmConstraints encConstraints = new AlgorithmConstraints(ConstraintType.WHITELIST,
					ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
			jwe.setContentEncryptionAlgorithmConstraints(encConstraints);
			jwe.setCompactSerialization(token);
			Assert.assertEquals("mf2c-sec should be private!", "private",
					jwe.getHeaders().getStringHeaderValue("mf2c-sec"));
			Assert.assertEquals("mf2c-sender is incorrect!", sender,
					jwe.getHeaders().getStringHeaderValue("mf2c-sender"));
			// mf2c-aclib
			Assert.assertEquals("mf2c-aclib is incorrect!", "1.0", jwe.getHeaders().getStringHeaderValue("mf2c-aclib"));
			Assert.assertEquals("typ is incorrect!", "JOSE", jwe.getHeaders().getStringHeaderValue("typ"));
			LOGGER.debug("headers: " + jwe.getHeaders().getFullHeaderAsJsonString());
		} catch (IllegalArgumentException e) {
			fail("Illegal Argument: " + e.getMessage());
		} catch (Exception e) {
			fail("Error test building a compact JWE w/o compression: " + e.getMessage());
		}
	}
	
	/**
	 * Test building a JWE with payload compression
	 */
	//@Ignore
	@Test
	public void testBReadingJWE() {
		//The test does not actually decrypt the token as we can't get a handle on the
		//recipient's private key: it is done all by the code, it will too much work to fake it 
		//at runtime
		LOGGER.info("running testBReadingJWE....");
		MsgTokenBuilder mtb = new MsgTokenBuilder();		

		try {
			// method either throw an exception or return the token string, no need to check
			token = mtb.setTyp(Type.JWE).setEnableCompression(true).setSecPolicy(Security.PRIVATE).setRecipients(did).setMsgPayload(message).build();
			//
			String[] jwsA = CompactSerializer.deserialize(token);
			Assert.assertTrue(jwsA.length == 5);
			//
			JsonWebEncryption jwe = new JsonWebEncryption();
			AlgorithmConstraints algConstraints = new AlgorithmConstraints(ConstraintType.WHITELIST,
					KeyManagementAlgorithmIdentifiers.RSA1_5); // use matching key wrapping algorithm
			jwe.setAlgorithmConstraints(algConstraints);
			AlgorithmConstraints encConstraints = new AlgorithmConstraints(ConstraintType.WHITELIST,
					ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
			jwe.setContentEncryptionAlgorithmConstraints(encConstraints);
			jwe.setCompactSerialization(token);
			//the getMessage method includes checking signature integrity
			Assert.assertEquals("Zip element should be defined!", "DEF", jwe.getHeaders().getStringHeaderValue("zip"));
			//Assert.assertTrue("compressed payload should be shorter than the message",message.length() > jwsA[3].length());
		}catch (Exception e) {
			fail("Error test reading a signed JWE w/o compression: " + e.getMessage());
		}
	}
	

}
