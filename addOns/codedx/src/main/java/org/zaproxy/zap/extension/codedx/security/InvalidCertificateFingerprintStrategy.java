package org.zaproxy.zap.extension.codedx.security;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

public class InvalidCertificateFingerprintStrategy implements InvalidCertificateStrategy {

	private final String fingerprint;
	private final boolean acceptPermanently;

	public InvalidCertificateFingerprintStrategy(String fingerprint, boolean acceptPermanently) {
		this.fingerprint = fingerprint.replaceAll("\\s", "");
		this.acceptPermanently = acceptPermanently;
	}

	@Override
	public CertificateAcceptance checkAcceptance(Certificate cert, CertificateException certError) {
		try {
			byte[] encoded = InvalidCertificateDialogStrategy.getSHA1(cert.getEncoded());
			String obsPrint = InvalidCertificateDialogStrategy.toHexString(encoded, "");
			if(obsPrint.equalsIgnoreCase(fingerprint)){
				if(acceptPermanently)
					return CertificateAcceptance.ACCEPT_PERMANENTLY;
				else
					return CertificateAcceptance.ACCEPT_TEMPORARILY;
			} else {
				return CertificateAcceptance.REJECT;
			}
		} catch (CertificateEncodingException e) {
			return CertificateAcceptance.REJECT;
		}
	}
}
