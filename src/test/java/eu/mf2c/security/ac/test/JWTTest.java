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

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.apache.log4j.Logger;
import org.jose4j.base64url.Base64Url;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwx.CompactSerializer;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import eu.mf2c.security.ac.MsgTokenBuilder;
import eu.mf2c.security.ac.exception.MsgTokenBuilderException;
import eu.mf2c.security.ac.utility.AgentSingleton;
import eu.mf2c.security.ac.utility.Security;
import eu.mf2c.security.ac.utility.Type;

/**
 * Test generating and validating an Agent
 * Identity JWT.  The JWT is structured as a signed JWS 
 * with the JWT claims as payload.
 * <p>
 * author Shirley Crompton
 * email  shirley.crompton@stfc.ac.uk
 * org Data Science and Technology Group,
 *      UKRI Science and Technology Council
 * Created 23 May 2019
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class JWTTest {
	/** Message Logger */
	protected static Logger LOGGER = org.apache.log4j.Logger.getLogger(JWTTest.class);
	/** JWT compact serialization String */
	public static String token;
	/** JWT claim attributes 
	public static JwtClaims claims;*/
	// this is the local Agent's did
	/** sender device id */
	public static String sender;
	/** List of recipient device ids */
	public static String[] recs;
	/** JWK of this Agent instance */
	public static RsaJsonWebKey jwk;
	
	
	/**
	 * {@inheritDoc}
	 * <p>
	 * @throws java.lang.Exception	on errors
	 */
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		sender = AgentSingleton.getInstance().getDid();
		recs = new String[2];
		recs[0]= "0f999d8fb78cbe9995507ef5a198f999ac89a3ae03b95e79d4ebfb8888c20d54e9a5d9b9c41f88c782d1f67b32231d31b4fada8d2f9dd31a4d884681b784ec5a";
		recs[1] = UUID.randomUUID().toString();
		jwk = AgentSingleton.getInstance().getJwk();
		/*
		JwtClaims claims = new JwtClaims();
		// These are reserved attributes
		claims.setIssuer(sender); // who creates the token and signs it
		claims.setAudience(rec); // only 1 recipient
		claims.setExpirationTimeMinutesInTheFuture(10); // time when the token will expire (10 minutes from now)
		claims.setGeneratedJwtId(); // a unique identifier for the token
		claims.setIssuedAtToNow(); // when the token was issued/created (now)
		claims.setNotBeforeMinutesInThePast(2); // time before which the token is not yet valid (2 minutes ago)*/
	}

	/**
	 * {@inheritDoc}
	 * @throws java.lang.Exception	on errors
	 */
	@AfterClass
	public static void tearDownAfterClass() throws Exception {
		token = null;
		//claims = null;
		sender = null;
		recs = null;
		jwk = null;
	}

	/**
	 * {@inheritDoc}
	 * @throws java.lang.Exception	on errors
	 */
	@Before
	public void setUp() throws Exception {
	}

	/**
	 * {@inheritDoc}
	 * @throws java.lang.Exception	on errors
	 */
	@After
	public void tearDown() throws Exception {
	}
	/**
	 * Test building a JWT
	 */
	@Test
	public void testABuildJWT() {
		LOGGER.info("running testABuildJWT....");

		MsgTokenBuilder mtb = new MsgTokenBuilder();		

		try {
			// method either throw an exception or return the token string, no need to check
			//token = mtb.setEnableCompression(false).setSecPolicy(Security.PROTECTED).setRecipients(did).setMsgPayload(message).build();
			
			token = mtb.setTyp(Type.JWT).setRecipients(recs).build();
			LOGGER.debug("Token String :\n" + token);
			//
			String[] jwsA = CompactSerializer.deserialize(token);
			Assert.assertTrue(jwsA.length == 3);
			Assert.assertTrue("there should be signature data!", !jwsA[2].isEmpty());
			//
			JwtConsumer jwtConsumer = new JwtConsumerBuilder().setRequireExpirationTime() // the JWT must have an expiration
					// time
					.setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for
					// clock skew
					// .setRequireSubject() // the JWT must have a subject claim
					.setExpectedIssuer(sender) // whom the JWT needs to have been issued by
					.setExpectedAudience(recs[1]) // to whom the JWT is intended for
					.setVerificationKey(jwk.getKey()) // verify the signature with the public key
					.setJwsAlgorithmConstraints( // only allow the expected signature algorithm(s) in the given context
							new AlgorithmConstraints(ConstraintType.WHITELIST, // which is only RS256 here
									AlgorithmIdentifiers.RSA_USING_SHA256))
					.build(); // create the JwtConsumer instance

			
				// Validate the JWT and process it to the Claims
				JwtClaims jwtClaims = jwtConsumer.processToClaims(token);
				LOGGER.info("JWT validation succeeded! " + jwtClaims);
				//
				
			} catch (InvalidJwtException e) {
				// InvalidJwtException will be thrown, if the JWT failed processing or
				// validation in anyway.
				// Hopefully with meaningful explanations(s) about what went wrong.
				fail("Invalid JWT! " + e);

				// Programmatic access to (some) specific reasons for JWT invalidity is also
				// possible
				// should you want different error handling behavior for certain conditions.

				// Whether or not the JWT has expired being one common reason for invalidity
				if (e.hasExpired()) {
					try {
						fail("JWT expired at " + e.getJwtContext().getJwtClaims().getExpirationTime());
					} catch (MalformedClaimException e1) {
						LOGGER.error("Error trying to access claims for expiration time!" );
					}
				}

				// Or maybe the audience was invalid
				if (e.hasErrorCode(ErrorCodes.AUDIENCE_INVALID)) {
					try {
						fail("JWT had wrong audience: " + e.getJwtContext().getJwtClaims().getAudience());
					} catch (MalformedClaimException e1) {
						LOGGER.error("Error trying to access claims for audience!" );
					}
				}
			} catch (IllegalArgumentException | MsgTokenBuilderException ee) {
				fail("build JWT Exception: " + ee.getMessage());
			}
	}

}
