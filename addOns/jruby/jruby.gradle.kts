import org.zaproxy.gradle.addon.AddOnStatus

description = "Allows Ruby to be used for ZAP scripting - templates included"

zapAddOn {
    addOnName.set("Ruby Scripting")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/ruby-scripting/")
    }
}

dependencies {
    implementation("org.jruby:jruby-complete:1.7.4")

    testImplementation(project(":testutils"))
}
