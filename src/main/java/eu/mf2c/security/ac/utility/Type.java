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

/**
 * An {@link java.lang.Enum <em>Enum</em>} of token supported.
 * <ul>
 * <li>PLAIN &#58; Plain text token</li>
 * <li>JWE &#58; Encrypted Json Web Encryption token</li>
 * <li>JWS &#58; Signed Json Web Signature token</li>
 * <li>JWT &#58; Signed Json Web Token with JWT Claims as payload.</li>
 * </ul>
 * <p>
 * author Shirley Crompton
 * email  shirley.crompton@stfc.ac.uk
 * org Data Science and Technology Group,
 *      UKRI Science and Technology Council
 * Created 22 May 2019
 */
public enum Type {
	//NONE,
	/** plain text token */
	PLAIN,
	/** encrypted JSON Web encryption token */
	JWE,
	/** signed JSON Web Signature token */
	JWS,
	/** signed JSON Web token with JWT Claims as payload */
	JWT
}
