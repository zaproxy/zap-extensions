/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.zaproxy.zap.extension.codedx.security;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;

public interface ExtraCertManager {

	/**
	 * Add a certificate that will be accepted until some event (as determined
	 * by the implementation of this interface) occurs, causing it to be
	 * "forgotten".
	 * 
	 * @param cert
	 */
	void addTemporaryCert(Certificate cert) throws IOException, GeneralSecurityException;

	/**
	 * Add a certificate that will be accepted until this manager is "purged".
	 * Certificates added in this way will generally be written to disk, and
	 * will be available upon restarting the program.
	 * 
	 * @param cert
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	void addPermanentCert(Certificate cert) throws IOException, GeneralSecurityException;

	/**
	 * Remove all certificates that have been added via
	 * {@link #addTemporaryCert(Certificate)}.
	 */
	void purgeTemporaryCerts() throws IOException, GeneralSecurityException;

	/**
	 * Remove all certificates that have been added via
	 * {@link #addPermanentCert(Certificate)}.
	 */
	void purgePermanentCerts() throws IOException, GeneralSecurityException;

	/**
	 * Remove all certificates that have been added either by
	 * {@link #addTemporaryCert(Certificate)} or
	 * {@link #addPermanentCert(Certificate)}.
	 */
	void purgeAllCerts() throws IOException, GeneralSecurityException;

	/**
	 * Return a representation of this manager as a KeyStore instance.
	 * @return A new KeyStore that represents the contents of this certificate
	 *         manager
	 */
	KeyStore asKeyStore() throws IOException, GeneralSecurityException;
}
