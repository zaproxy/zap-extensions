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
package org.zaproxy.zap.extension.pscanrulesAlpha;

/**
 * a class to encapsulate a CVE (in a very minimal fashion)
 * @author 70pointer@gmail.com
 *
 */
public class CVE {
	private String cve;
	private Double cvss;
	

	public String getCve() {
		return cve;
	}
	public Double getCvss() {
		return cvss;
	}
	
	public CVE (String cve, Double cvss) {
		this.cve = cve;
		this.cvss = cvss;			
	}
}