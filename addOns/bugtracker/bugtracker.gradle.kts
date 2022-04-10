description = "Bug Tracker extension."

tasks.withType<JavaCompile> {
    options.compilerArgs = options.compilerArgs - "-Werror" + "-proc:none"
}

zapAddOn {
    addOnName.set("Bug Tracker")
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/bug-tracker/")
    }
}

dependencies {
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
