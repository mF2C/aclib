package eu.mf2c.security.ac.data;

import org.apache.log4j.Logger;
import org.jose4j.jwk.JsonWebKey;

import eu.mf2c.security.ac.utility.CCClient;

public class Recipient extends Sender {
	/** Message logger */
	protected Logger LOGGER = Logger.getLogger(Recipient.class);	
	/** Encrypted AES key for the recipient */
	private byte[] encryptionKey; 
	
	/**
	 * Construct an instant
	 * <p>
	 * @param deviceID	The recipient&#39;s identifier
	 * @throws IllegalStateException	if failing to initialise 
	 */
	public Recipient(String deviceID) throws IllegalStateException {
		super.did = deviceID;
		super.initialise();
	}
	
	/**
	 * Getter for the recipient&#39;s RSA encrypted key.  This is the
	 * encrypted AES content encryption key for this particular 
	 * recipient.
	 * <p> 
	 * @return the encryptionKey	the encrypted key
	 */
	public byte[] getEncryptionKey() {
		return encryptionKey;
	}
	/**
	 * Setter for the recipient&#39;s RSA encrypted key.  This is the
	 * encrypted AES content encryption key for this particular 
	 * recipient.
	 * <p> 
	 * @param encryptionKey the encryptionKey to set
	 */
	public void setEncryptionKey(byte[] encryptionKey) {
		this.encryptionKey = encryptionKey;
	}





	/**
	public static void main(String[] args) {
		//
		Recipient r = new Recipient("abcdeff");
		r.getJwk();
		r.getPubKey();

	}*/

}
