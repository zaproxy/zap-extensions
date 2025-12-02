import org.zaproxy.gradle.addon.AddOnStatus

description = "Provides the GraalVM JavaScript engine for ZAP scripting."

zapAddOn {
    addOnName.set("GraalVM JavaScript")
    addOnStatus.set(AddOnStatus.ALPHA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/graalvm-javascript/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }

        bundledLibs {
            libs.from(configurations.runtimeClasspath)
        }

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">=1.37.0")
                }
                register("scripts") {
                    version.set(">=45.15.0")
                }
            }
        }
    }
}

crowdin {
    configuration {
        tokens.put("%helpPath%", "")
    }
}

dependencies {
    zapAddOn("commonlib")
    zapAddOn("scripts")

    implementation(libs.graaljs.graaljs)
    implementation(libs.graaljs.jsScriptEngine)

    testImplementation(project(":testutils"))
}
