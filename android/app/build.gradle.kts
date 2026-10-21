// SPDX-License-Identifier: Apache-2.0
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.skhoron.twofa.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.skhoron.twofa"
        minSdk = 30 // setUserAuthenticationParameters(int, int) появился в API 30
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    sourceSets {
        // Общее JVM-ядро, которое проверяется тестами в core/jvm
        getByName("main").java.srcDir("../../core/jvm/src")
    }
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.biometric:biometric:1.1.0")
}