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
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * This X509TrustManager implementation allows invalid certificates to possibly
 * be accepted by the decision of an {@link InvalidCertificateStrategy} that is
 * passed as a constructor argument. Certificates added in this way will be
 * added via a {@link ExtraCertManager}, causing the underlying trust manager to
 * be reloaded.
 * 
 * Adapted from the implementation at <a href=
 * "https://jcalcote.wordpress.com/2010/06/22/managing-a-dynamic-java-trust-store/"
 * >"Managing a Dynamic Java Trust Store"</a> (blog post)
 */
public class ReloadableX509TrustManager implements X509TrustManager {

	/* package-private */final ExtraCertManager certManager;
	private final InvalidCertificateStrategy invalidCertStrat;
	private X509TrustManager tmDelegate;

	public ReloadableX509TrustManager(ExtraCertManager certManager, InvalidCertificateStrategy invalidCertStrat) throws IOException,
			GeneralSecurityException {
		this.certManager = certManager;
		this.invalidCertStrat = invalidCertStrat;
		reloadTrustManager();
	}

	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		tmDelegate.checkClientTrusted(chain, authType);
	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		try {
			tmDelegate.checkServerTrusted(chain, authType);
		} catch (CertificateException cx) {

			/*
			 * At this point, we have come across an apparently-invalid
			 * certificate. We use the `InvalidCertificateStrategy` to decide
			 * what to do about it; either reject it (rethrow the exception), or
			 * accept it. If accepting, the certificate can be added
			 * "temporarily" or "permanently", which is done via the
			 * `ExtraCertManager`.
			 */
			Certificate cert = chain[0];
			CertificateAcceptance certAcceptance = invalidCertStrat.checkAcceptance(cert, cx);

			switch (certAcceptance) {
			case REJECT:
				throw cx;

			case ACCEPT_TEMPORARILY:
				try {
					certManager.addTemporaryCert(cert);
					reloadTrustManager();
				} catch (IOException | GeneralSecurityException e) {
					// wrap errors from the cert manipulation
					throw new CertificateException("Error handling temporary acceptance of the certificate", e);
				}
				// now retry the trust check
				tmDelegate.checkServerTrusted(chain, authType);
				break;

			case ACCEPT_PERMANENTLY:
				try {
					certManager.addPermanentCert(cert);
					reloadTrustManager();
				} catch (IOException | GeneralSecurityException e) {
					// wrap errors from the cert manipulation
					throw new CertificateException("Error handling permanent acceptance of the certificate", e);
				}
				// now retry the trust check
				tmDelegate.checkServerTrusted(chain, authType);
				break;
				
			default:
				throw cx;
			}
		}
	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		return tmDelegate.getAcceptedIssuers();
	}

	/* package-private */
	final void reloadTrustManager() throws IOException, GeneralSecurityException {
		KeyStore ks = certManager.asKeyStore();

		// initialize a new TMF with the KeyStore we just created
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(ks);

		// acquire an X509 trust manager from the TMF
		// and update the `tmDelegate` to that value
		TrustManager[] tms = tmf.getTrustManagers();
		for (TrustManager tm : tms) {
			if (tm instanceof X509TrustManager) {
				tmDelegate = (X509TrustManager) tm;
				return;
			}
		}

		// should have returned in the `for` loop above
		throw new NoSuchAlgorithmException("No X509TrustManager in TrustManagerFactory");
	}

}
