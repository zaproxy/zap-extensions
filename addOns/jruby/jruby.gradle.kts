import org.zaproxy.gradle.addon.AddOnStatus

description = "Allows Ruby to be used for ZAP scripting - templates included"

zapAddOn {
    addOnName.set("Ruby Scripting")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/ruby-scripting/")
        dependencies {
            addOns {
                register("scripts") {
                    version.set(">=45.2.0")
                }
            }
        }
    }
}

dependencies {
    implementation("org.jruby:jruby-complete:1.7.4")

    testImplementation(project(":testutils"))
}
