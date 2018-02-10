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

import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public interface InvalidCertificateStrategy {
	/**
	 * Determine what to do with a certificate (reject, accept temporarily, or
	 * accept permanently)
	 * 
	 * @param cert A (probably invalid) certificate
	 * @param certError An exception (or null) that caused the certificate to be
	 *            considered invalid
	 * @return A CertificateAcceptance value that determines whether (and for
	 *         how long) the certificate should be considered valid.
	 */
	CertificateAcceptance checkAcceptance(Certificate cert, CertificateException certError);
}
