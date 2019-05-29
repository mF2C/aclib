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

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.apache.log4j.Logger;
import org.jose4j.base64url.Base64;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.StringUtil;

import eu.mf2c.security.ac.exception.CCClientException;

/**
 * A basic TCP client to communicate with the CAU-Client block 
 * within an mF2C Agent.
 * <p>
 * author Shirley Crompton
 * email  shirley.crompton@stfc.ac.uk
 * org Data Science and Technology Group,
 *      UKRI Science and Technology Council
 * Created 27 Feb 2019
 */
public class CCClient {
	/** message logger */
	protected static Logger LOGGER = Logger.getLogger(CCClient.class);
	/** local CAU-client port */
	protected int cau_client_port = 46065; //default
	/** socket */
	private Socket socket; //client socket
	private boolean isConnected = false;
	private OutputStream out = null; // write to server
	private BufferedInputStream in = null; //read from server
	
	/**
	 * Construct an instance 
	 */
	public CCClient() {
		//default constructor
	}
	/**
	 * Construct an instance with the specified port number for the CAU Client
	 * <p>
	 * @param cau_client_port
	 
	public CCClient(int cau_client_port) {
		super();
		if(cau_client_port != 0) {
			this.cau_client_port = cau_client_port;
		}
	}*/
	
	/**
	 * Start a TCP connection to the local Cau&#45;Client 
	 * <p>
	 * @throws IOException on connection error
	 */
	public void startConnection() throws IOException {
	        this.socket = new Socket(InetAddress.getLoopbackAddress(), cau_client_port); //CAU-client is on the same network
	        this.isConnected = true;
	    }
	/**
	 * Call the local Cau&#45;Client to get the public key of the Agent identified by its device id.
	 * The CAU&#45;Client will in turn query the CAU for the public key.
	 * <p>
	 * @param did	the target&#39;s device id.
	 * @return	the public key of target Agent in PEM format
	 * @throws CCClientException 	on error
	 */ 
    public String getPublicKey(String did) throws CCClientException {
    	String keyPEM = null;
    	//prepare message
    	Map<String, Object> request = new HashMap<String, Object>();
		request.put("did", did);
		String msg = request + "\n"; //needs CR for EOF signal
		try {
			//connect to cau-client
			if(!this.isConnected) {    		  	
	    		startConnection();
	    	}
			out = this.socket.getOutputStream(); //for writing message
			in = new BufferedInputStream(this.socket.getInputStream()); // for reading response
			//			
			out.write(msg.getBytes());
			out.flush();
			// wait for response, should be the token
			LOGGER.debug("waiting for cau-client response....");
			// Create buffer:
			byte[] buffer = new byte[1024]; //expect a public key pem
			int bytesRead = 0;
			// read in the response and write to the BAOS
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			while ((bytesRead = in.read(buffer, 0, 1024)) != -1) {
				//
				baos.write(buffer, 0, bytesRead); // keep adding to the buffer
				LOGGER.debug("Client recieved " + bytesRead + " bytes");
			}
			baos.flush();
			//
			keyPEM = new String(baos.toByteArray(), StandardCharsets.UTF_8);
			LOGGER.debug("public key PEM from CAU-client : " + keyPEM);
			// could write it to a file
			baos.close();
    	}catch(Exception e) {
    		throw new CCClientException(e);
    	}finally{
    		this.stopConnection();
    	}
        return keyPEM;
    }
	 	/**
	 	 * Terminates the TCP connection to the local 
	 	 */
	    public void stopConnection() {
	        try {
	        	if(in != null) {
	        		in.close();
	        	}
		    	if(out != null) {
		    		out.close();
		    	}
		    	if(socket != null) {
					socket.close();		    		
		    	}
			} catch (IOException e) {
				LOGGER.error("Error closing in/out-put streams or socket! " + e.getMessage());
			}finally {
		    	this.isConnected = false;
		    }
	    }

	
	
	///////class needs to return an RSA JWK
	/**
	 * Get the RSA JsonWebKey of the Agent identified by its device id.
	 * <p>
	 * @param did	the target&#39;s device id.
	 * @return	the RSA JsonWebKey of the target Agent
	 * @throws CCClientException	on error
	 */
	public RsaJsonWebKey getTargetJWK(String did) throws CCClientException{
		//
		//CAU client queries the leader's CAU to get the public key
		String pem = this.getPublicKey(did);
		if(pem != null && !pem.isEmpty()) {
			pem = pem.replaceAll("\\n", "").replace("-----BEGIN RSA PUBLIC KEY-----", "").replace("-----END RSA PUBLIC KEY-----", "");
		    // String publicKeyPEM = pem.replace("-----BEGIN RSA PUBLIC KEY-----\n", "");
		    // publicKeyPEM = publicKeyPEM.replace("-----END RSA PUBLIC KEY-----", "");
		}else {
			throw new CCClientException("Failed to retrieve public key for : " + did);
		}
		//go ahead
		byte [] decoded = Base64.decode(pem);
	    X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
	    RsaJsonWebKey jwk = null;
	    
		try {
			KeyFactory kf = KeyFactory.getInstance("RSA");
			RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(spec);
			jwk = (RsaJsonWebKey) PublicJsonWebKey.Factory.newPublicJwk(pubKey);
			LOGGER.debug("Generated jwk: " + jwk.toJson());
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | JoseException e) {
			// 
			throw new CCClientException(e);
		}
	    return jwk;
	}
	
	/////////////////////////////stub methods : replaced with real calls to CAU //////////
	/**
	 * Get a random UUID String
	 * <p>
	 * @return the generatead UUID String
	 */
	@Deprecated
	private String getUUIDStr() {
		//get a random 128-bit long String as the device id
		return UUID.randomUUID().toString();
	}
	/**
	 * Generate a 2048 length RSA public key.
	 * <p>
	 * @return the public key or null if in error
	 */
	@Deprecated
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
	/**
	 * Generate a RSAJsonWebKey wrapping a 2048 length RSA keypair
	 * <p>
	 * @return the generated RsaJsonWebKey or null if in error
	 */
	@Deprecated
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
