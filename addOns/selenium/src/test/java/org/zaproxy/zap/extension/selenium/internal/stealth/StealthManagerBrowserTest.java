package org.zaproxy.zap.extension.selenium.internal.stealth;

import io.github.bonigarcia.wdm.WebDriverManager;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.chromium.ChromiumDriver;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.extension.selenium.SeleniumScriptUtils;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.not;

public class StealthManagerBrowserTest {

    private static ChromiumDriver chromeDriver;

    @BeforeAll
    static void setupAll() {
        ChromeOptions options = new ChromeOptions();
        options.addArguments("--headless=new");
        options.addArguments("--no-sandbox");
        options.addArguments("--disable-dev-shm-usage");
        options.addArguments("--window-size=1920,1080");

        WebDriverManager.chromedriver().setup();
        chromeDriver = (ChromiumDriver) WebDriverManager.chromedriver().capabilities(options).create();

        StealthManager stealthManager = new StealthManager();
        SeleniumScriptUtils ssutils = new SeleniumScriptUtils(chromeDriver, 0, Browser.CHROME_HEADLESS.getId(), null, 0);
        stealthManager.browserLaunched(ssutils);

        chromeDriver.get("data:text/html,<html></html>");
    }

    @AfterAll
    static void afterAll() {
        chromeDriver.quit();
    }

    @Test
    void chrome_userAgentOverride() {
        // When user agent is retrieved
        String userAgent = String.valueOf(chromeDriver.executeScript("return navigator.userAgent"));
        // Then headless mode is not identified
        assertThat(userAgent, not(containsString("Headless")));
        // Then Linux is not identified
        assertThat(userAgent, not(containsString("Linux")));
    }

    @Test
    void chrome_vendorOverride() {
        // When vendor is retrieved
        String vendor = String.valueOf(chromeDriver.executeScript("return navigator.vendor"));
        // Then Google Inc. is returned
        assertThat(vendor, equalTo("Google Inc."));
    }

    @Test
    void chrome_webdriverOverride() {
        // When webdriver is retrieved
        Object webdriver = chromeDriver.executeScript("return navigator.webdriver");
        // Then false is returned
        assertThat(webdriver, equalTo(false));
    }

    @Test
    void chrome_loadTimes() {
        // When loadTimes is retrieved
        String loadTimes = String.valueOf(chromeDriver.executeScript("return window.chrome.loadTimes"));
        // Then timing is present
        assertThat(loadTimes, not(emptyString()));
    }

    @Test
    void chrome_hardwareconcurrency() {
        // When hardware concurrency is retrieved
        Integer hardwareConcurrency = Integer.parseInt(String.valueOf(chromeDriver.executeScript("return navigator.hardwareConcurrency")));
        // Then probably is returned
        assertThat(hardwareConcurrency, greaterThan(1));
    }

    @Test
    void chrome_outerDimensionsOverride() {
        // When outerWidth is retrieved
        Long outerWidth = (Long) chromeDriver.executeScript("return window.outerWidth");
        // Then positive value is returned
        assertThat(outerWidth, greaterThan(0L));

        // When outerHeight is retrieved
        Long outerHeight = (Long) chromeDriver.executeScript("return window.outerHeight");
        // Then positive value is returned
        assertThat(outerHeight, greaterThan(0L));
    }

    @Test
    void chrome_appOverride() {
        // When window.chrome.app is retrieved
        String app = String.valueOf(chromeDriver.executeScript("return JSON.stringify(window.chrome.app)"));
        // Then app is present
        assertThat(app, not(emptyString()));
    }

    @Test
    void chrome_csiOverride() {
        // When window.chrome.app is retrieved
        String csi = String.valueOf(chromeDriver.executeScript("return JSON.stringify(window.chrome.csi)"));
        // Then csi is present
        assertThat(csi, not(emptyString()));
    }

}

