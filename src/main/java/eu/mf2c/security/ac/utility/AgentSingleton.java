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

import java.io.File;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;


/**
 * A singleton storing the Agent&#39;s credential and information.
 * <p>
 * author Shirley Crompton
 * email  shirley.crompton@stfc.ac.uk
 * org Data Science and Technology Group,
 *      UKRI Science and Technology Council
 * Created 26 Feb 2019
 */
public class AgentSingleton {
	/** Logger attribute */
	protected static Logger LOGGER = Logger.getLogger(AgentSingleton.class);
	/** An instance of the class */
	private static AgentSingleton instance = null;
	/** FQDN attribute 
	private String fqdn;*/
	/** X509 certificate of the agent */
	private static X509Certificate agentCert;
	/** device id **/
	private static String did;
	/** private key **/
	private static PrivateKey privKey;
	/** RSA JSON web key */
	private static RsaJsonWebKey jwk;
	/** status flag **/
	public static boolean initialised = false;

	/**
	 * Private constructor
	 */
	private AgentSingleton() {
		initialise();
	}
	
	/**
	 * Get an instance.  Create a new one if not yet instantiated.
	 * <p>
	 * @return an instance of the class.
	 */
	public static AgentSingleton getInstance() {
		if(instance == null) {
			instance = new AgentSingleton();
		}
		return instance;				
	}
	/**
	 * Initialise the global variables.  As there is a timing issue on when the library starts and 
	 * when the discovery process completes.  We let this be an external operation.
	 */
	public static void initialise() {
		//
		if(initialised == false) {
			//TODO CAU client to write device id to PKI volume
			//We pick up the agent cert (server.crt), private key (server.key) and device id from the shared volume pkidata
			try {
				//get deviceId (from the proposed CIMI resource?)
				did = new String(Files.readAllBytes(FileSystems.getDefault().getPath(File.separator + "pkidata", "deviceid.txt")));
				LOGGER.debug("Deviceid : " + did);
				//System.out.println("Deviceid : " + did);
				if(did == null) {
					LOGGER.error("Error getting device id! ");
					//7Mar19 not sure if this is vital yet, will let swallow the error for the moment
					//throw new AgentSingletonException("Error getting device id! Cannot continue....");
				}
				//get private Key, this will be private key pem written by cau client, so pkcs8 format
				String pkcs8 = new String(Files.readAllBytes(FileSystems.getDefault().getPath(File.separator + "pkidata", "server.key")));
				privKey = CredentialUtil.loadPKCS8PrivateKey(pkcs8);
				if(privKey == null) {
					return;
				}
				//System.out.println("got private key!");
				LOGGER.debug("got private key!");
				//get Agent X509 certificate
				String x509 = File.separator + "pkidata" + File.separator + "server.crt";
				agentCert = CredentialUtil.loadX509(x509);
				if(agentCert == null) {
					return;
				}
				//System.out.println("got certificate!");
				LOGGER.debug("got certificate!");
				//generate a JSON web key using the public and private key
				jwk = CredentialUtil.getJWK(agentCert.getPublicKey(), privKey);
				System.out.println("got JWK!");
				LOGGER.debug("got JWK!");
			}catch(Exception e) {
				LOGGER.error("Error getting agent's credential from shared docker volume: " + e.getMessage());
			}
			initialised = true;
			//LOGGER.debug("AgentSingleton initialised...");
		}		
	}

	/**
	 * Getter for the Agent&#39;s X.509 certificate
	 * <p>
	 * @return the {@link #agentCert} object
	 */
	public X509Certificate getAgentCert() {
		return agentCert;
	}

	/**
	 * Getter for the Agent&#39;s device id attribute
	 * <p>
	 * @return the {@link #did} object
	 */
	public String getDid() {
		return did;
	}
	
	/**
	 * Getter for the RSA Json web key attribute.
	 * <p>
	 * @return the {@link #jwk} object
	 */
	public RsaJsonWebKey getJwk() {
		return jwk;
	}

	
	
	
}
