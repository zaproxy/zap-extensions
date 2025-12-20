import org.zaproxy.gradle.addon.AddOnStatus

description = "Provides a BeanShell Console"

zapAddOn {
    addOnName.set("BeanShell Console")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/bean-shell/")
    }
}

dependencies {
    implementation(libs.beanshell.beanshell)
}

spotless {
    java {
        // Don't enforce the license, just the format.
        clearSteps()
        googleJavaFormatAosp()
    }
}
