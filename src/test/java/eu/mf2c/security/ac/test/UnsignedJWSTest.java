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
 * Tests building and reading unsigned Json Web Signature objects.
 * <p>
 * author Shirley Crompton
 * email  shirley.crompton@stfc.ac.uk
 * org Data Science and Technology Group,
 *      UKRI Science and Technology Council
 * Created 22 Mar 2019
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class UnsignedJWSTest {
	
	/** Message Logger */
	protected static Logger LOGGER = org.apache.log4j.Logger.getLogger(UnsignedJWSTest.class);
	/** JWS compact serialization String */
	public static String token;
	public static String message = "Well, as of this moment, they're on DOUBLE SECRET PROBATION! +"
			+ "Do you really care?  I don't. "
			+ "The silver fox quickly jumped over the fence.  As long as it doesn't"
			+ " eat my chickens...."
			+ "It can go as it pleases. :D"; 
	//this is the local Agent's did
	/** sender device id */
	public static 
	String sender = "0f848d8fb78cbe5615507ef5a198f660ac89a3ae03b95e79d4ebfb3466c20d54e9a5d9b9c41f88c782d1f67b32231d31b4fada8d2f9dd31a4d884681b784ec5a";
	
	/**
	 * @throws java.lang.Exception on errors
	 */
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		
	}

	/**
	 * @throws java.lang.Exception on errors
	 */
	@AfterClass
	public static void tearDownAfterClass() throws Exception {
		token = null;
		message = null;
		sender = null;
	}
	
	/**
	 * Test creating an unsigned JWS.
	 * The payload is not compressed.
	 */
	//@Ignore
	@Test
	public void testAUnsignedJWS_NC() {		
		LOGGER.info("running testUnsignedJWS_NC....");
		
		MsgTokenBuilder mtb = new MsgTokenBuilder();
		//get a random 128-bit long String as the device id
		//String did = UUID.randomUUID().toString();
		
		
		try {
			//method either throw an exception or return the token string, no need to check
			token = mtb.setEnableCompression(false).setSecPolicy(Security.PUBLIC).setMsgPayload(message).setTyp(Type.valueOf("PLAIN")).build();
			LOGGER.debug("Token string: \n" + token);
			//
			String[] jwsA = CompactSerializer.deserialize(token);
			Assert.assertTrue(jwsA.length == 3);
			Assert.assertEquals("there should be no signature data!", jwsA[2], "");
			//
			JsonWebSignature jws = new JsonWebSignature();
			jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.NONE);// flag unsecured JWS alg:none
			jws.setAlgorithmConstraints(AlgorithmConstraints.ALLOW_ONLY_NONE);
			jws.setCompactSerialization(token);
			Assert.assertEquals("mf2c-sec should be public!","public",jws.getHeaders().getStringHeaderValue("mf2c-sec"));
			Assert.assertEquals("mf2c-sender is incorrect!", sender, jws.getHeaders().getStringHeaderValue("mf2c-sender"));
			//mf2c-aclib
			Assert.assertEquals("mf2c-aclib is incorrect!", "1.0", jws.getHeaders().getStringHeaderValue("mf2c-aclib"));
			Assert.assertEquals("typ is incorrect!", "JOSE", jws.getHeaders().getStringHeaderValue("typ"));
		} catch (IllegalArgumentException e) {
			fail("Illegal Argument: " + e.getMessage());
		} catch (Exception e) {
			fail("Error testing unsigned JWS w/o compression: " + e.getMessage());
		}
	}
	/**
	 * Test reading an unsigned JWS.
	 * The payload is not compressed.
	 */
	//@Ignore
	@Test
	public void testBUnsignedJWS_NC_READ() {
		LOGGER.info("running testUnsignedJWS_NC_READ....");
		MsgTokenReader reader = new MsgTokenReader(token, Type.PLAIN);
		//
		try {
			Assert.assertEquals("The payload is not the same!",message, reader.handleToken());
		}catch (Exception e) {
			fail("Error testing unsigned JWS w/o compression: " + e.getMessage());
		}
	}
	/**
	 * Test creating and reading an unsigned JWS.
	 * The payload is compressed.
	 */
	@Test
	public void testCRoundtrip_UnsignedJWS() {
		token = null;
		LOGGER.info("running testCUnsignedJWS....");
		MsgTokenBuilder mtb = new MsgTokenBuilder();
		//
		try {
			//method either throw an exception or return the token string, no need to check
			token = mtb.setEnableCompression(true).setSecPolicy(Security.PUBLIC).setMsgPayload(message).setTyp(Type.PLAIN).build();
			//			
			JsonWebSignature jws = new JsonWebSignature();
			jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.NONE);// flag unsecured JWS alg:none
			jws.setAlgorithmConstraints(AlgorithmConstraints.ALLOW_ONLY_NONE);
			jws.setCompactSerialization(token);
			//
			Assert.assertEquals("Zip element should be defined!", "DEF", jws.getHeaders().getStringHeaderValue("zip"));
			Assert.assertTrue("Compressed payload should be smaller!",jws.getPayload().length() < message.length());
			//now read back
			MsgTokenReader reader = new MsgTokenReader(token, Type.valueOf("PLAIN"));
			Assert.assertEquals("The payload is not the same!",message, reader.handleToken());			
			
		} catch (IllegalArgumentException e) {
			fail("Illegal Argument: " + e.getMessage());
		} catch (Exception e) {
			fail("Error testing unsigned JWS w/o compression: " + e.getMessage());
		}
		
		
		
	}

	
	

}
