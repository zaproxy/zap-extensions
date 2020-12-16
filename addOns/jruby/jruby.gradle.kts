import org.zaproxy.gradle.addon.AddOnStatus

version = "8"
description = "Allows Ruby to be used for ZAP scripting - templates included"

zapAddOn {
    addOnName.set("Ruby Scripting")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/ruby-scripting/")
        notBeforeVersion.set("2.10.0")
    }
}

dependencies {
    implementation("org.jruby:jruby-complete:1.7.4")

    testImplementation(project(":testutils"))
}
