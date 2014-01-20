package org.zaproxy.zap.extension.saml;

import org.parosproxy.paros.Constant;

import java.util.ResourceBundle;

public class SamlI18n {
    private static ResourceBundle message;

    public static void init(){
        message = ResourceBundle.getBundle(SamlI18n.class.getPackage().getName()
                + ".Messages", Constant.getLocale());
    }

    public static String getMessage(String key) {
        if (key != null && message!=null && message.containsKey(key)) {
            return message.getString(key);
        }
        return "";
    }
}
