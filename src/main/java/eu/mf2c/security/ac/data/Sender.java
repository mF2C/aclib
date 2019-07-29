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

import org.apache.log4j.Logger;
import org.jose4j.jwk.JsonWebKey;

import eu.mf2c.security.ac.tcp.ACLibServer;
import eu.mf2c.security.ac.utility.AgentSingleton;
import eu.mf2c.security.ac.utility.CCClient;

/**
 * Token sender.
 * <p>
 * author Shirley Crompton
 * email  shirley.crompton@stfc.ac.uk
 * org Data Science and Technology Group,
 *      UKRI Science and Technology Council
 * Created 21 Mar 2019
 */
public class Sender {
	/** Message logger */
	protected Logger LOGGER = Logger.getLogger(Sender.class);
	/** Identifier */
	public String did;
	/** Json web key */
	private JsonWebKey jwk; //we use an RSA jwk 2048 bits
	/** RSA public key 
	private java.security.PublicKey pubKey; */
	//note no private key, only gets this in AgentSingleton
	
	/**
	 * Construct an instance
	 * <p>
	 * @param deviceID	The agent&#39;s identifier
	 * @throws IllegalStateException	if error initialising the class
	 */
	public Sender(String deviceID) throws IllegalStateException {
		this.did = deviceID;
		this.initialise();
	}
	/**
	 * Default constructor
	 */
	public Sender() {
		
	}
	/**
	 * Initialise object by getting it&#39;s RSA public key
	 * using the {@link eu.mf2c.security.ac.utility.CCClient <em>CauClient</em>}
	 * and to derive a Json Web Key from the public key.
	 * <p> 
	 * @throws IllegalStateException	if failing to get the public key or the JWK
	 */
	protected void initialise() throws IllegalStateException {
		try {
			//get the public key of the recipient
			CCClient client = new CCClient(ACLibServer.cau_client_port);	
			if(this.did.equals(AgentSingleton.getInstance().getDid())) {
				this.jwk = AgentSingleton.getInstance().getJwk();
			}else {
				this.jwk = client.getTargetJWK(did); //ccclient converts the pem to jwk				
				//
				if(this.jwk == null) {
					throw new IllegalStateException("Failed to get RSA JWK for Agent(" + this.did + "), cannot proceed..." );
				}
				this.jwk.setKeyId(this.did);				
			}
		}catch(Exception e) {
			throw new IllegalStateException("Failed to initialise class: " + e.getMessage());
		}
	}
	/**
	 * Getter for the {@link #jwk} attribute
	 * <p>
	 * @return the json web key
	 */
	public JsonWebKey getJwk() {
		return this.jwk;
	}
	/**
	 * Getter for the {@link #pubKey} attribute 
	 * <p>
	 * @return the pubKey
	 
	public java.security.PublicKey getPubKey() {
		return this.pubKey;
	}*/

	/**
	 * @param args
	 
	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}*/

}
