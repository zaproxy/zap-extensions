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

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;

/**
 * Represents an ordered list of {@link X509TrustManager}s with additive trust.
 * If any one of the composed managers trusts a certificate chain, then it is
 * trusted by the composite manager.
 * 
 * This is necessary because of the fine-print on {@link SSLContext#init}: Only
 * the first instance of a particular key and/or trust manager implementation
 * type in the array is used. (For example, only the first
 * javax.net.ssl.X509KeyManager in the array will be used.)
 * 
 * <a href="http://stackoverflow.com/questions/1793979/registering-multiple-keystores-in-jvm">
 * see StackOverflow</a> and the
 * <a href="http://codyaray.com/2013/04/java-ssl-with-multiple-keystores">related
 * blog post</a>
 * 
 * @author codyaray
 * @since 4/22/2013
 * @see
 */
public class CompositeX509TrustManager implements X509TrustManager {

	private final List<X509TrustManager> trustManagers = new LinkedList<>();

	/**
	 * Initializes the composite trust manager, copying all of the non-null
	 * entries in the given <code>trustManagers</code> list into its own
	 * internal list.
	 * 
	 * @param trustManagers A list of (potentially null) trust managers.
	 */
	public CompositeX509TrustManager(List<X509TrustManager> trustManagers) {
		for (X509TrustManager tm : trustManagers) {
			if (tm != null) this.trustManagers.add(tm);
		}
	}

	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		for (X509TrustManager trustManager : trustManagers) {
			try {
				trustManager.checkClientTrusted(chain, authType);
				return; // someone trusts them. success!
			} catch (CertificateException e) {
				// maybe someone else will trust them
			}
		}
		throw new CertificateException("None of the TrustManagers trust this certificate chain");
	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		for (X509TrustManager trustManager : trustManagers) {
			try {
				trustManager.checkServerTrusted(chain, authType);
				return; // someone trusts them. success!
			} catch (CertificateException e) {
				// maybe someone else will trust them
			}
		}
		throw new CertificateException("None of the TrustManagers trust this certificate chain");
	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		List<X509Certificate> certificates = new LinkedList<>();
		for (X509TrustManager trustManager : trustManagers) {
			for (X509Certificate cert : trustManager.getAcceptedIssuers()) {
				certificates.add(cert);
			}
		}
		return certificates.toArray(new X509Certificate[certificates.size()]);
	}

}