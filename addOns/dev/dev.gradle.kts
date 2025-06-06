description = "An add-on to help with development of ZAP."

repositories {
    mavenCentral()
}

zapAddOn {
    addOnName.set("Dev Add-on")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/dev-add-on/")

        bundle {
            baseName.set("org.zaproxy.addon.dev.Messages")
            prefix.set("dev")
        }

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">=1.17.0")
                }
                register("network") {
                    version.set(">=0.7.0")
                }
                register("authhelper") {
                    version.set(">=0.26.0") // Or whichever version you need
                }
            }
        }
    }
}

dependencies {
    zapAddOn("network")
    zapAddOn("commonlib")
    zapAddOn("authhelper")

    compileOnly(libs.log4j.core)

    testImplementation(project(":testutils"))
    testImplementation(libs.log4j.core)
}

tasks.named("compileJava") {
    dependsOn(":addOns:authhelper:enhance")
}
