package org.openqa.selenium.browserlaunchers;

import org.openqa.selenium.Capabilities;
import org.openqa.selenium.Proxy;

/**
 * Workaround for issue #397 of GhostDriver.
 *
 * @see <a href="https://github.com/detro/ghostdriver/issues/397">GhostDriver&apos;s issue #397</a>
 */
public class Proxies {

    public static Proxy extractProxy(Capabilities capabilities) {
        return Proxy.extractFrom(capabilities);
    }
}