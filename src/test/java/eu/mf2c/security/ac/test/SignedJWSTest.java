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
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.CompactSerializer;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import eu.mf2c.security.ac.MsgTokenBuilder;
import eu.mf2c.security.ac.MsgTokenReader;
import eu.mf2c.security.ac.utility.AgentSingleton;
import eu.mf2c.security.ac.utility.Security;

/**
 * Test building and reading signed JWS objects.
 * <p>
 * author Shirley Crompton email shirley.crompton@stfc.ac.uk org Data Science
 * and Technology Group, UKRI Science and Technology Council Created 22 Mar 2019
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SignedJWSTest {
	/** Message Logger */
	protected static Logger LOGGER = org.apache.log4j.Logger.getLogger(UnsignedJWSTest.class);
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
	public static String did = UUID.randomUUID().toString();
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
	//@Ignore
	@Test
	public void tesAtBuildingJWS_UC() {
		LOGGER.info("running testUnsignedJWS_NC....");

		MsgTokenBuilder mtb = new MsgTokenBuilder();		

		try {
			// method either throw an exception or return the token string, no need to check
			//token = mtb.setEnableCompression(false).setSecPolicy(Security.PROTECTED).setRecipients(did).setMsgPayload(message).build();
			token = mtb.setEnableCompression(false).setSecPolicy(Security.PROTECTED).setMsgPayload(message).build();
			LOGGER.debug("Token String :\n" + token);
			//
			String[] jwsA = CompactSerializer.deserialize(token);
			Assert.assertTrue(jwsA.length == 3);
			Assert.assertTrue("there should be signature data!", !jwsA[2].isEmpty());
			//
			JsonWebSignature jws = new JsonWebSignature();
			jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
			jws.setCompactSerialization(token);
			Assert.assertEquals("mf2c-sec should be protected!", "protected",
					jws.getHeaders().getStringHeaderValue("mf2c-sec"));
			Assert.assertEquals("mf2c-sender is incorrect!", sender,
					jws.getHeaders().getStringHeaderValue("mf2c-sender"));
			// mf2c-aclib
			Assert.assertEquals("mf2c-aclib is incorrect!", "1.0", jws.getHeaders().getStringHeaderValue("mf2c-aclib"));
			Assert.assertEquals("typ is incorrect!", "JOSE", jws.getHeaders().getStringHeaderValue("typ"));
		} catch (IllegalArgumentException e) {
			fail("Illegal Argument: " + e.getMessage());
		} catch (Exception e) {
			fail("Error test building a signed JWS w/o compression: " + e.getMessage());
		}
	}

	//use local Agent's public key to verify signature
	/**
	 * Test reading an uncompressed JWS, including verifying the signature data.
	 */
	//@Ignore
	@Test
	public void testBReadingJWS_UC() {
		LOGGER.info("running testReadingJWS_UC....");
		MsgTokenReader reader = new MsgTokenReader(token);
		//
		try {
			//the getMessage method includes checking signature integrity
			Assert.assertEquals("The payload is not the same!",message, reader.getMessage());
		}catch (Exception e) {
			fail("Error test reading a signed JWS w/o compression: " + e.getMessage());
		}
	}
	/**
	 * Do a roundtrip test of a signed JWS with a compressed payload.
	 */
	@Test
	public void testCRoundTripJWS() {
		token = null;
		LOGGER.info("running testCRoundTripJWS....");
		MsgTokenBuilder mtb = new MsgTokenBuilder();		

		try {
			// method either throw an exception or return the token string, no need to check
			token = mtb.setEnableCompression(true).setSecPolicy(Security.PROTECTED).setMsgPayload(message).build();
			//
			JsonWebSignature jws = new JsonWebSignature();
			jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
			jws.setCompactSerialization(token);
			//set key to verify signature
			jws.setKey(AgentSingleton.getInstance().getJwk().getPublicKey());
			Assert.assertEquals("Zip element should be defined!", "DEF", jws.getHeaders().getStringHeaderValue("zip"));
			Assert.assertTrue("Compressed payload should be smaller!",jws.getPayload().length() < message.length());
			//
			//now read back
			MsgTokenReader reader = new MsgTokenReader(token);
			Assert.assertEquals("The payload is not the same!",message, reader.getMessage());			
			
		} catch (IllegalArgumentException e) {
			fail("Illegal Argument: " + e.getMessage());
		} catch (Exception e) {
			fail("Error testing roundtripping of signed JWS w/o compression: " + e.getMessage());
		}
	}
	
	
}
