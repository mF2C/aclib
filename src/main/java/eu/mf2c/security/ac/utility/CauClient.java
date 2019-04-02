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
package eu.mf2c.security.ac.utility;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.UUID;

import org.apache.log4j.Logger;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;

import eu.mf2c.security.ac.exception.CauClientException;

/**
 * A basic TCP client to communicate with the CAU-Client block 
 * within an mF2C Agent.
 * <p>
 * author Shirley Crompton
 * email  shirley.crompton@stfc.ac.uk
 * org Data Science and Technology Group,
 *      UKRI Science and Technology Council
 * Created 27 Feb 2019
 * <p>
 */
public class CauClient {
	/** message logger */
	protected static Logger LOGGER = Logger.getLogger(CauClient.class);
	/**
	 * Get the public of the Agent identified by its device id.
	 * <p>
	 * @param did	the target&#39;s device id.
	 * @return	the public key of target Agent
	 * @throws CauClientException 	on error
	 */
	public PublicKey getTargetPubKey(String did) throws CauClientException {
		//:TODO
		//CAU client should query the leader's CAU to get the public key
		//temporary code to enable development
		return this.getPubKey();
		//end temporary code
	}	
	
	
	
	/**
	 * Get the RSA JsonWebKey of the Agent identified by its device id.
	 * <p>
	 * @param did	the target&#39;s device id.
	 * @return	the RSA JsonWebKey of the target Agent
	 * @throws CauClientException	on error
	 */
	public RsaJsonWebKey getTargetJWK(String did) throws CauClientException{
		//:TODO
		//CAU client should query the leader's CAU to get the public key
		//temporary code to enable development
		return this.getRsaJWK();
		//end temporary code
	}
	
	
	/////////////////////////////stub methods :TODO replace this with real calls to CAU //////////
	
	private String getUUIDStr() {
		//get a random 128-bit long String as the device id
		return UUID.randomUUID().toString();
	}
	private PublicKey getPubKey() {
		KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(2048, new SecureRandom());
			KeyPair keypair = keyGen.generateKeyPair();
			//either put it in a keystore or to a file
			
			
			return keypair.getPublic();
		} catch (NoSuchAlgorithmException e) {
			LOGGER.error("Error generating RSA keypair: " + e.getMessage());			
		} 
		return null;
	}
	
	private RsaJsonWebKey getRsaJWK() {
		KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(2048, new SecureRandom());
			KeyPair keypair = keyGen.generateKeyPair();			
			RsaJsonWebKey rsaJwk = (RsaJsonWebKey) PublicJsonWebKey.Factory.newPublicJwk(keypair.getPublic());
	        rsaJwk.setPrivateKey(keypair.getPrivate());
	        return rsaJwk;
		} catch (Exception e) {
			LOGGER.error("Error generating RSA keypair: " + e.getMessage());			
		} 
		return null;
		
	}
	
}
