description = "Bug Tracker extension."

zapAddOn {
    addOnName.set("Bug Tracker")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/bug-tracker/")
    }
}

dependencies {
    compileOnly("com.infradna.tool:bridge-method-annotation:1.18") {
        exclude(group = "org.jenkins-ci")
    }
    compileOnly("com.github.spotbugs:spotbugs-annotations:3.1.12")
    implementation("com.j2bugzilla:j2bugzilla:2.2.1") {
        // Not needed.
        exclude(group = "junit")
    }
    implementation("org.kohsuke:github-api:1.303") {
        // Not needed.
        exclude(group = "com.infradna.tool")
        // Provided by ZAP.
        exclude(group = "commons-codec")
        // Provided by ZAP.
        exclude(group = "commons-io")
    }
}
