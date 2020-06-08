version = "0.0.1"
description = "Inspect and attack GraphQL endpoints."

zapAddOn {
    addOnName.set("GraphQL Support")
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
    }

    apiClientGen {
        api.set("org.zaproxy.addon.graphql.GraphQlApi")
        messages.set(file("src/main/resources/org/zaproxy/addon/graphql/resources/Messages.properties"))
    }
}

dependencies {
    compileOnly("org.zaproxy:zap:2.10.0-SNAPSHOT")

    implementation("com.google.code.gson:gson:2.8.6")
    implementation("com.graphql-java:graphql-java:15.0")
}

repositories {
    maven {
        url = uri("https://oss.sonatype.org/content/repositories/snapshots/")
    }
}
