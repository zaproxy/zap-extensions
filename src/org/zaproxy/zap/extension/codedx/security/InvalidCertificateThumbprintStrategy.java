package org.zaproxy.zap.extension.codedx.security;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

public class InvalidCertificateThumbprintStrategy implements InvalidCertificateStrategy {

	private final String thumbprint;
	private final boolean acceptPermanently;

	public InvalidCertificateThumbprintStrategy(String thumbprint, boolean acceptPermanently) {
		this.thumbprint = thumbprint.replaceAll("\\s", "");
		this.acceptPermanently = acceptPermanently;
	}

	@Override
	public CertificateAcceptance checkAcceptance(Certificate cert, CertificateException certError) {
		try {
			byte[] encoded = InvalidCertificateDialogStrategy.getSHA1(cert.getEncoded());
			String obsThumb = InvalidCertificateDialogStrategy.toHexString(encoded, "");
			if(obsThumb.equalsIgnoreCase(thumbprint)){
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
