package org.zaproxy.addon.dev.auth.totp;


import org.zaproxy.addon.authhelper.internal.AuthenticationStep;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;

public class TestTotp {

    public static String generateCurrentCode() {
        AuthenticationStep step = new AuthenticationStep();
        step.setType(AuthenticationStep.Type.TOTP_FIELD);
        step.setTotpSecret("JBSWY3DPEHPK3PXP");
        step.setTotpPeriod(30);
        step.setTotpDigits(6);
        step.setTotpAlgorithm("SHA1");

        UsernamePasswordAuthenticationCredentials dummyCreds =
            new UsernamePasswordAuthenticationCredentials("user", "pass");

        return step.getTotpCode(dummyCreds).toString();
    }

    public static boolean isCodeValid(String inputCode) {
        return generateCurrentCode().equals(inputCode);
    }
}
