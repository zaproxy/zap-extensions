plugins {
    `java-gradle-plugin`
    id("com.diffplug.gradle.spotless") version "3.20.0"
}

repositories {
    mavenCentral()
    maven {
        // Required for dependencies of com.infradna.tool:bridge-method-annotation.
        url = uri("https://repo.jenkins-ci.org/releases/")
        content {
            includeGroup("org.jenkins-ci")
        }
    }
}

spotless {
    java {
        licenseHeaderFile(file("../gradle/spotless/license.java"))
        googleJavaFormat().aosp()
    }

    kotlinGradle {
        ktlint()
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "utf-8"
    options.compilerArgs = listOf("-Xlint:all", "-Xlint:-path", "-Xlint:-options", "-Werror")
}

dependencies {
    implementation("io.github.bonigarcia:webdrivermanager:3.3.0")
    // Force use of 1.11 needed by ZAP plugin.
    implementation("commons-codec:commons-codec:1.11")
    implementation("org.kohsuke:github-api:1.95")
    // Include annotations used by the above library to avoid compiler warnings.
    compileOnly("com.google.code.findbugs:findbugs-annotations:3.0.1")
    compileOnly("com.infradna.tool:bridge-method-annotation:1.18")
    implementation("com.github.zafarkhaja:java-semver:0.9.0")
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}