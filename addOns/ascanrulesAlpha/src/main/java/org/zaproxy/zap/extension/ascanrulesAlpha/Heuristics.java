package org.zaproxy.zap.extension.ascanrulesAlpha;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

public class Heuristics {
    public static boolean isParameterPassword(String parameter) {
        String[] passwordParams = new String[]{"pass","password","pw","pword","passwrd"};
        AtomicBoolean found = new AtomicBoolean(false);
        Arrays.asList(passwordParams).stream().forEach( x -> {
            if (x.equals(parameter)) {
                found.set(true);
            }
        });
        return found.get();
    }

    public static boolean isUserLoggedIn(String response) {
        String[] patterns = new String[]{"log out","welcome","logout","hello"};
        AtomicBoolean found = new AtomicBoolean(false);
        Arrays.asList(patterns).stream().forEach( x -> {
            if (response.contains(x)) {
                found.set(true);
            }
        });
        return found.get();
    }

    public static boolean isJSONValid(String test) {
        try {
            new JSONObject(test);
        } catch (JSONException ex) {
            try {
                new JSONArray(test);
            } catch (JSONException ex1) {
                return false;
            }
        }
        return true;
    }
}
