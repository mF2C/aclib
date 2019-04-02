/**
 * Copyright 2018-2- UKRI Science and Technology Facilities Council

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
 * An {@link java.lang.Enum <em>Enum</em>} of security level supported.
 * <ul>
 * <li>PUBLIC &#58; Public data, no special protection required</li>
 * <li>PROTECTED &#58;  Data that are not secret but needs integrity protection</li>
 * <li>PRIVATE &#58; Personal sensitive and confidential data that needs to be encrypted.</li>
 * </ul>
 * <p>
 * author Shirley Crompton
 * email  shirley.crompton@stfc.ac.uk
 * org Data Science and Technology Group,
 *      UKRI Science and Technology Council
 * Created 26 Feb 2019
 */
public enum Security {
	//NONE,
	/** for data which needs no special protection */
	PUBLIC,
	/** for data which is not secret but needs integrity protection */
    PROTECTED,
    /** for personal sensitive or confidential data */
    PRIVATE;
}
