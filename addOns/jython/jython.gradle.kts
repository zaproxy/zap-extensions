import org.zaproxy.gradle.addon.AddOnStatus

version = "12"
description = "Allows Python to be used for ZAP scripting - templates included"

zapAddOn {
    addOnName.set("Python Scripting")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.10.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/python-scripting/")
    }
}

dependencies {
    implementation("org.python:jython-standalone:2.7.2")

    testImplementation(project(":testutils"))
}
