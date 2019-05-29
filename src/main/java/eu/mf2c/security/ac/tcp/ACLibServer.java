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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.HashMap;

import org.apache.log4j.Logger;

/**
 * A TCP server wrapping the AC Library to enable loose coupling with the other
 * blocks in an Agent. Intra Agent communication will be over private Docker
 * network.
 * <p>
 * author Shirley Crompton email shirley.crompton@stfc.ac.uk org Data Science
 * and Technology Group, UKRI Science and Technology Council Created 29 Mar 2019
 */
public class ACLibServer {
	/** Message logger attribute */
	protected static Logger LOGGER = Logger.getLogger(ACLibServer.class);
	/** Server socket attribute */
	private ServerSocket sSocket;
	/** Client socket attribute 
	private Socket conn = null;*/
	/** server output stream object /
	private OutputStream os = null;*
	/** flag to control state of socket */
	private boolean isRunning = true;
	/** port number, default to 46080 */
	protected int port = 46080;
	/** IP address, default to 0.0.0.0 */
	protected String ip = "0.0.0.0"; //to be replaced by a Docker variable
	/** CAU Client port number, default to 46065 */
	protected int cau_client_port = 46065;

	/**
	 * Constructor
	 * <p>
	 * 
	 * @param args
	 *            the IP and port to run the server on.
	 */
	public ACLibServer(String... args) {

		String[] params = args;
		if (params.length == 0) {
			LOGGER.debug("no arguments, using default configs...");
			return;
		} else if (params.length == 1) {
			LOGGER.debug("one argument, assuming it is the CAU-client port...");
			this.cau_client_port = Integer.valueOf(args[0]);
		} else if (params.length == 3) {
			LOGGER.debug("three argument...");
			this.ip = args[0];
			this.port = Integer.valueOf(args[1]);
			this.cau_client_port = Integer.valueOf(args[2]);
		}
	}
	/**
	 * Set up the server
	 * <p>
	 * @throws IOException on error
	 */
	public void configServer() throws IOException {
		// for local test only. auto port n#, max 2 in queue on any local address
		//sSocket = new ServerSocket(this.port, 2, InetAddress.getByName(this.ip));
		// deployment
		 sSocket = new ServerSocket(this.port , 20, InetAddress.getByName(this.ip));
		// //IT1 fixed port n#, max 20 in queue , use ip 0 for running in Docker
		//
		sSocket.setReuseAddress(true);
		LOGGER.debug("Socket running on port : " + sSocket.getLocalPort() + ", waiting for connection");
	}

	/**
	 * Run the server in a loop until a shutdown signal is received.
	 */
	public void runServer() {
		
		while (true) {
			try {
				// get the connection socket
				// conn = sSocket.accept();
				// start a new handler thread to handle the call. It handles closing the client socket
				new ReqHandler(sSocket.accept()).start();
				LOGGER.debug("after spawing reqHandler thread, server returning to waiting....");
				//
			} catch (Exception e) {
				this.isRunning = false;
				LOGGER.debug("Server encountered exception " + e.getMessage());
				/** handled by reqHandler
				if (os != null) {
					try {
						os.write(e.getMessage().getBytes());
					} catch (IOException e1) {
						//
						LOGGER.error("Error trying to close server output stream!");
					}
				}*/
			}
		}
	}

	/**
	 * Shutdown server
	 */
	protected void shutdown() {
		//this is not a threaded class, so not much use 
		LOGGER.debug("Server about to shutdown....");
		if (isRunning) {
			isRunning = false;
		}
	}

	/**
	 * Entry point to the application. The
	 * <p>
	 * 
	 * @param args
	 *            the IP and port number to run the server on
	 */
	public static void main(String[] args) {
		ACLibServer server = null;
		if (args.length == 3 || args.length == 1 || args.length == 0) {
			server = new ACLibServer(args);
			try {
				server.configServer();
				server.runServer();
			}catch (Exception e){
				LOGGER.debug("Error configuring or running server : " + e.getMessage());
			}
		} else {
			throw new RuntimeException(
					"Usage: [ServerIP] [port] [CAU-Client port]\nEither provide the arguments or none to use the default setting!");
		}
	}
}
