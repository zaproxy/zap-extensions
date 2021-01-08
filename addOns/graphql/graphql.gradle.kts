version = "0.3.0"
description = "Inspect and attack GraphQL endpoints."

zapAddOn {
    addOnName.set("GraphQL Support")
    zapVersion.set("2.10.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/graphql-support/")
    }

    apiClientGen {
        api.set("org.zaproxy.addon.graphql.GraphQlApi")
        options.set("org.zaproxy.addon.graphql.GraphQlParam")
        messages.set(file("src/main/resources/org/zaproxy/addon/graphql/resources/Messages.properties"))
    }
}

dependencies {
    implementation("com.google.code.gson:gson:2.8.6")
    implementation("com.graphql-java:graphql-java:15.0")

    testImplementation(project(":testutils"))
}
