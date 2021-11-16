/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.httpsinfo;

import java.math.BigInteger;

public class Certification {
    private String subjectDN;
    private String signingAlgorithm;
    private String certificateFingerPrint;
    private String issuerDN;
    private String notValidBefore;
    private String notValidAfter;
    private String certificateSerialNumber;
    private String certificateVersion;
    private String selfSignedCertificate;
    private String trustState;
    private String validState;

    public String getSubjectDN() {
        return subjectDN;
    }

    public String getSigningAlgorithm() {
        return signingAlgorithm;
    }

    public String getCertificateFingerPrint() {
        return certificateFingerPrint;
    }

    public String getIssuerDN() {
        return issuerDN;
    }

    public String getNotValidBefore() {
        return notValidBefore;
    }

    public String getNotValidAfter() {
        return notValidAfter;
    }

    public String getCertificateSerialNumber() {
        return certificateSerialNumber;
    }

    public String getCertificateVersion() {
        return certificateVersion;
    }

    public String getSelfSignedCertificate() {
        return selfSignedCertificate;
    }

    public String getTrustState(){return trustState;}
    public String getValidState(){return validState;}

    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }

    public void setSigningAlgorithm(String signingAlgorithm) {
        this.signingAlgorithm = signingAlgorithm;
    }

    public void setCertificateFingerPrint(String certificateFingerPrint) {
        this.certificateFingerPrint = certificateFingerPrint;
    }

    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

    public void setNotValidBefore(String notValidBefore) {
        this.notValidBefore = notValidBefore;
    }

    public void setNotValidAfter(String notValidAfter) {
        this.notValidAfter = notValidAfter;
    }

    public void setCertificateSerialNumber(String certificateSerialNumber) {
        this.certificateSerialNumber = certificateSerialNumber;
    }

    public void setCertificateVersion(String certificateVersion) {
        this.certificateVersion = certificateVersion;
    }

    public void setSelfSignedCertificate(String selfSignedCertificate) {
        this.selfSignedCertificate = selfSignedCertificate;
    }

    public void setTrustState(String trustState){ this.trustState=trustState; }
    public void setValidState(String validState){ this.validState=validState; }
}

