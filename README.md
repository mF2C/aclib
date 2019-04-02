AC Library (version mF2c IT2 demo)

The library provides utility functions to implement the mF2C data security policy.  The policy defines three different message security levels:

1) public - for data not requiring protection
2) protected - for data which needs to be integrity protected but is not confidential
3) private - for data which needs both integrity and confidentiality protection.

The library uses a consistent data packaging structure to encapsulate messages and supporting metadata.  It leverages existing mF2C PKI and the CAU security middleware to provide credentials for signing and encrypting the message payloads according to the security level specified by caller.  The library adopts the Json Web Signature (JWS - RFC 7515) specification for signing Protected messages and the Json Web Encryption (JWE - RFC 7516) one for encrypting Private confidential messages.  Encrypted message tokens protect data payload confidentiality beyond the communication endpoints (as in TLS) as a recipient needs to use its private key issued by mF2C PKI to decrypt a token's content encryption key before it can successfully retrieve the message payload.  For consistency purposes, the library also provides a method to encapsulate public messages as unsigned JWSs.  Callers may optionally compress the payload to optimise its size.

The library is deployed as an Agent block and runs an TCP socket server to listen to calls for creating a message token and extracting message payload from a provided token from other blocks within the same Agent.  (Please see the AC Lib.pdf in the resources folder for a presentation on its features and usages.) The library in turn uses the local CAU-client block as an entry point the the CAU middleware for retrieving senders' and recipients' public keys.

Use Maven to build a fat jar with all dependencies.  The jar is located in the target folder and the javadoc in the target\site\apidocs folder.

The server uses built-in configuration of:
1) 	aclib server IP = 0.0.0.0
2)  aclib server port = 46080
3)  cau-client port = 46065

You can override all three parameters or just the cau-client port.  The application accepts 0 (using all default values), 1 (overriding cau-client port value) or 3 (overriding all three values) arguments:

		java -jar mf2c-aclib-jar-with-dependencies.jar [ip] [port] [cau-client port]
		
Please note that you may use the library to create and read unsigned JWS token for public messages only at the moment.  We need the back end CAU plumbing in place to provide Agent's credentials before we can use it for creating/reading signed JWS and JWE.

Shirley Crompton
UKRI-STFC
2 April 2019