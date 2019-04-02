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
package eu.mf2c.security.ac.tcp;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.StringUtil;

import eu.mf2c.security.ac.MsgTokenBuilder;
import eu.mf2c.security.ac.MsgTokenReader;
import eu.mf2c.security.ac.exception.MsgTokenBuilderException;
import eu.mf2c.security.ac.exception.MsgTokenReaderException;
import eu.mf2c.security.ac.exception.ReqHandlerException;
import eu.mf2c.security.ac.utility.Security;

/**
 * Request handler for servicing a client call.
 * <p>
 * author Shirley Crompton email shirley.crompton@stfc.ac.uk org Data Science
 * and Technology Group, UKRI Science and Technology Council Created 29 Mar 2019
 */
public class ReqHandler extends Thread {
	/** Message logger attribute */
	protected static Logger LOGGER = Logger.getLogger(ReqHandler.class);
	/** Client socket attribute */
	public Socket sock;

	/**
	 * Constructor
	 * <p>
	 * 
	 * @param s
	 *            The client connection object
	 */
	public ReqHandler(Socket s) {
		this.sock = s;
	}

	/**
	 * Run method for this handler thread. It processes the incoming message, gets
	 * the correct type of token created and sends it back to the client.
	 * <p>
	 * If there are exceptions, an error code is returned&#58;
	 * <ul>
	 * <li>err1 &#58; integrity error for JWS and JWE</li>
	 * <li>err2 &#58; credential error for JWS and JWE</li>
	 * <li>err3 &#58; other processing errors</li>
	 * </ul>
	 */
	@Override
	public void run() {
		BufferedReader inReader = null;
		//BufferedInputStream in = null;
		OutputStream os = null;
		try {
			os = sock.getOutputStream();
			LOGGER.debug("Connection received from " + sock.getInetAddress().getHostName() + " : " + sock.getPort());
			// set up input read
			//
			LOGGER.debug("Before reading in message ....");
			inReader = new BufferedReader(new InputStreamReader(sock.getInputStream(), StandardCharsets.UTF_8));
			String message = inReader.readLine(); // should be an UTF8 String
			//
			String token = null;
			if (message != null && !message.isEmpty()) {
				LOGGER.debug("Incoming message: " + message);
				//
				try {
					token = handleRequest(message);
					if (token == null || token.isEmpty()) {
						throw new Exception("Token is null/empty!");
					}
				} catch (Exception e) {
					//
					String errCode = "err3";
					// System.out.println("Cause :" + e.getCause() + " errMsg: " + e.getMessage());
					// For compact JWE: ERR1 includes key unwrapping error as JOSE4j generates a
					// random one if it can't unwrap the key
					// so we got an tag authen error
					if (e.getMessage().contains("Token signature is invalid")
							|| e.getMessage().contains("Authentication tag check failed")) {
						errCode = "err1";
						// for JJWE, my code check if the Agent owner is a recipient, so we get this
						// error
					} else if (e.getMessage().contains("Agent is not an intended recipient")) {
						// we don't have any credential to decrypt the encrypted_key
						errCode = "err2";
					}
					os.write(StringUtil.getBytesUtf8(errCode));
					os.flush();
					return;
				}
				// ok, no exception and we have a token
				String tokenM = token + "\n";
				byte[] msgBytes = tokenM.getBytes();
				LOGGER.debug("about to stream token String (" + token.length() + "bytes) to client....");
				os = this.sock.getOutputStream();
				//
				os.write(msgBytes);
				os.flush();
			}
		} catch (Exception e) {
			LOGGER.debug("ReqHandler encountered exception " + e.getMessage());
			if (os != null) {
				try {
					os.write(StringUtil.getBytesUtf8("err3"));
					os.flush();
				} catch (IOException e1) {
					LOGGER.error("Error trying to close output stream!");
				}
			}
		} finally {			
			try {
				os.close();
				inReader.close();
				LOGGER.debug("Request handler closing client connection ....");
				if (this.sock.isConnected()) {
					this.sock.close();
				}
			} catch (IOException e) {
				LOGGER.error("Error trying to close client connection!");
			}
		}
	}
	/**
	 * Parse a token String to get the plaintext payload.
	 * <p>
	 * @param token 	the token String
	 * @return			the plaintext payload
	 * @throws MsgTokenReaderException	on error extracting the payload
	 */
	public String readToken(String token) throws MsgTokenReaderException {
		LOGGER.debug("About to read a token.....");
		//
		MsgTokenReader reader = new MsgTokenReader(token);
		return reader.getMessage();
	}
	/**
	 * Build a token using the passed in arguments
	 * <p>
	 * @param m	the client request message
	 * @return	the token String
	 * @throws ReqHandlerException		on error processing the request
	 * @throws MsgTokenBuilderException 	on error building the token
	 * @throws JoseException 	on error extracting the request arguments
	 */
	public String buildToken(String m) throws ReqHandlerException, MsgTokenBuilderException, JoseException {

		LOGGER.debug("About to build a token....");

		Map<String, Object> params = parseInput(m);
		String payload = (String) params.get("payload");
		if (payload == null || payload.isEmpty()) {
			throw new ReqHandlerException("No payload, cannot build token !");
		}
		boolean cFlag = false;
		if (params.get("comp") != null && params.get("comp").equals("t")) {
			cFlag = true;
		}
		MsgTokenBuilder builder = new MsgTokenBuilder();
		Security sec = null;
		if (params.get("sec") != null) {
			if (params.get("sec").equals("pub")) {
				LOGGER.debug("Requesting an unsigned JWS....");
				sec = Security.PUBLIC;
			} else if (params.get("sec").equals("pro")) {
				LOGGER.debug("Requesting an JWS....");
				sec = Security.PROTECTED;
			} else if (params.get("sec").equals("pri")) {
				LOGGER.debug("Requesting an JEW....");
				sec = Security.PRIVATE;
				if (params.get("recs") != null) {
					// System.out.println("about to cast recs object to List<String>...");
					@SuppressWarnings("unchecked")
					List<String> recs = (List<String>) params.get("recs");
					// System.out.println("about to cast recs object to String array...");
					// wouldn't let me do a list.toArray....
					if (recs != null && recs.size() > 0) {
						String[] recipients = new String[recs.size()];
						int i = 0;
						for (String r : recs) {
							// System.out.println("putting " + r + " to " + i + " pos");
							recipients[i] = r;
							i++;
						}
						builder.setRecipients(recipients);
					} else {
						throw new ReqHandlerException("failed to extract recipients for private message! Cannot proceed!");
					}
				} else {
					throw new ReqHandlerException("No recipients for private message! Cannot proceed!");
				}
			} else {
				throw new ReqHandlerException("Unknown security policy!  Cannot proceed...");
			}
		} else {
			throw new ReqHandlerException("No security policy, cannot build token !");
		}
		builder = builder.setEnableCompression(cFlag).setMsgPayload(payload).setSecPolicy(sec);
		//
		return builder.build();
	}
	/**
	 * Determine if caller is request a token or to get the payload.
	 * <p>
	 * @param message	the client request
	 * @return			either a token String or the token payload.
	 * @throws ReqHandlerException	on error processing the request
	 * @throws MsgTokenReaderException		on error extracting the plaintext payload
	 * @throws MsgTokenBuilderException 	on error building the token
	 * @throws JoseException	on error parsing the Json message String
	 */
	public String handleRequest(String message) throws ReqHandlerException, MsgTokenBuilderException, MsgTokenReaderException, JoseException {
		// here I assume that the caller has guarded for empty or null m!!!!!!
		// handle the request
		if (message.contains("payload") && message.contains("sec")) {
			return buildToken(message);
		} else {// assumes that it is getPayloadText
			return readToken(message);
		}
	}
	/**
	 * Extract the arguments in a token request.
	 * <p>
	 * @param message	the request message String
	 * @return			a key&#45;value map of the arguments
	 * @throws JoseException	on error parsing the Json message String
	 */
	private Map<String, Object> parseInput(String message) throws JoseException {		
		Map<String, Object> params = JsonUtil.parseJson(message);
		LOGGER.debug("payload : " + params.get("payload"));
		LOGGER.debug("recs : " + (params.get("recs") == null ? "null" : params.get("recs")));
		LOGGER.debug("comp : " + params.get("comp"));
		LOGGER.debug("sec : " + params.get("sec"));
		return params;
	}

	/**
	 * @param args
	 
	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}*/

}
