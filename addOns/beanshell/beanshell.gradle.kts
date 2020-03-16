import org.zaproxy.gradle.addon.AddOnStatus

version = "7"
description = "Provides a BeanShell Console"

zapAddOn {
    addOnName.set("BeanShell Console")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/bean-shell/")
    }
}

dependencies {
    implementation("org.beanshell:bsh:2.0b4")
}

spotless {
    java {
        // Don't enforce the license, just the format.
        clearSteps()
        googleJavaFormatAosp(project)
    }
}
