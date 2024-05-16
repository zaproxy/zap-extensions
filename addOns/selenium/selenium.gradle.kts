import org.zaproxy.gradle.addon.AddOnStatus

description = "WebDriver provider and includes HtmlUnit browser"

val selenium by configurations.creating
configurations.api { extendsFrom(selenium) }

zapAddOn {
    addOnName.set("Selenium")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/selenium/")

        dependencies {
            addOns {
                register("network") {
                    version.set(">=0.2.0")
                }
                register("commonlib") {
                    version.set(">=1.23.0")
                }
            }
        }

        bundledLibs {
            libs.from(selenium)
        }
    }

    apiClientGen {
        api.set("org.zaproxy.zap.extension.selenium.SeleniumAPI")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/selenium/resources/Messages.properties"))
    }
}

dependencies {
    var seleniumVersion = "4.21.0"
    selenium("org.seleniumhq.selenium:selenium-java:$seleniumVersion")
    selenium("org.seleniumhq.selenium:htmlunit3-driver:4.20.0")
    implementation(libs.log4j.slf4j) {
        // Provided by ZAP.
        exclude(group = "org.apache.logging.log4j")
    }

    zapAddOn("commonlib")
    zapAddOn("network")

    testImplementation(project(":testutils"))
}
