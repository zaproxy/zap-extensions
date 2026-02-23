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

spotless {
    java {
        target(
            fileTree(projectDir) {
                include("src/**/*.java")
                exclude("src/main/java/org/zaproxy/zap/extension/selenium/internal/FirefoxBinary.java")
            },
        )
    }
}

dependencies {
    compileOnly(libs.log4j.core)

    selenium(libs.selenium.seleniumJava)
    selenium(libs.selenium.htmlunit3Driver) {
        // Do not expose the newer version to dependents, exclude and change to implementation.
        exclude(group = "org.apache.commons", module = "commons-lang3")
    }
    implementation("org.apache.commons:commons-lang3:3.18.0")
    implementation(libs.log4j.slf4j)

    zapAddOn("commonlib")
    zapAddOn("network")

    testImplementation(project(":testutils"))
}

val webdriverProjectPath =
    when {
        org.gradle.internal.os.OperatingSystem.current().isMacOsX -> ":addOns:webdrivers:webdrivermacos"
        org.gradle.internal.os.OperatingSystem.current().isLinux -> ":addOns:webdrivers:webdriverlinux"
        else -> ":addOns:webdrivers:webdriverwindows"
    }

tasks.register<Sync>("prepareTestWebdrivers") {
    val wdProject = project(webdriverProjectPath)
    dependsOn(wdProject.tasks.named("generateZapAddOnManifest"))
    from(wdProject.layout.buildDirectory.dir("webdrivers"))
    into(layout.buildDirectory.dir("test-zap-webdrivers"))
}

tasks.withType<Test>().configureEach {
    if (name == "test") {
        dependsOn("prepareTestWebdrivers")
        systemProperties["zap.test.webdrivers.home"] =
            layout.buildDirectory.dir("test-zap-webdrivers").get().asFile.absolutePath
    }
}
