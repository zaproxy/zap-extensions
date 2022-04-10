import org.zaproxy.gradle.addon.AddOnStatus

description = "WebDriver provider and includes HtmlUnit browser"

zapAddOn {
    addOnName.set("Selenium")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/selenium/")

        dependencies {
            addOns {
                register("network") {
                    version.set(">=0.2.0")
                }
            }
        }
    }

    apiClientGen {
        api.set("org.zaproxy.zap.extension.selenium.SeleniumAPI")
        options.set("org.zaproxy.zap.extension.selenium.SeleniumOptions")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/selenium/resources/Messages.properties"))
    }
}

dependencies {
    api("org.seleniumhq.selenium:selenium-server:3.141.59")
    api("org.seleniumhq.selenium:htmlunit-driver:2.54.0")
    api("com.codeborne:phantomjsdriver:1.4.4")

    compileOnly(parent!!.childProjects.get("network")!!)

    testImplementation(parent!!.childProjects.get("network")!!)
    testImplementation(project(":testutils"))
}
