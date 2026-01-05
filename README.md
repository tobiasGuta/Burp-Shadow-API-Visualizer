# Shadow API Visualizer (Burp Suite Extension)

Shadow API Visualizer is a Burp Suite extension designed to help bug hunters and penetration testers discover hidden, unused, or "shadow" API endpoints by statically analyzing client-side code in real-time.

## Description
Modern Single Page Applications (SPAs) often contain references to API endpoints in their JavaScript bundles (main.js, app.js, etc.) that are not immediately triggered by browsing the site.

These "Shadow APIs" often include:
* Dev/Admin endpoints (e.g., /api/admin/reset)
* Deprecated versions (e.g., /v1/legacy/user)
* Debug features (e.g., /api/debug/metrics)

Shadow API Visualizer automatically extracts these paths and presents them in a tree view, allowing you to visualize the attack surface that normal proxy history misses.

## Features
* **Passive JS Scanning:** Automatically scans all proxied JavaScript files for API-like patterns using regex.
* **Shadow vs. Live Status:**
    * **Red Nodes:** "Shadow" endpoints found in code but never requested by the browser. These are high-value targets.
    * **Green Nodes:** Verified endpoints that have been actively visited in live traffic.
* **Source Code Highlighting:** Click any node to see the exact line of JavaScript where the endpoint was defined, highlighted automatically in the response viewer.
* **Workflow Integration:** Right-click any finding to "Send to Repeater" or "Copy URL".
* **Smart Deduplication:** Filters out duplicate findings to keep the workspace clean.

## Installation

### Requirements
* Burp Suite Professional or Community Edition
* Java 21 (or compatible JDK)

### Build from Source
1. Clone this repository:
   git clone https://github.com/tobiasGuta/Burp-Shadow-API-Visualizer.git

2. Open the project in IntelliJ IDEA.

3. Build the JAR using Gradle:
   Run ./gradlew jar (or use the IntelliJ Gradle tab: Tasks -> build -> jar).

4. The output file will be located in build/libs/ShadowApiVisualizer-1.0-SNAPSHOT.jar.

### Load into Burp Suite
1. Open Burp Suite.
2. Navigate to Extensions -> Installed.
3. Click Add.
4. Select Java as the extension type.
5. Select the .jar file you just built.

## Usage
1. Ensure the extension is loaded (Look for the "Shadow Visualizer" tab in the top bar).
2. Browse your target application normally using Burp's embedded browser.
3. As you browse, the extension will populate the tree with API paths found in .js files.
4. Analyze the Tree:
    * Focus on Red Nodes. These are paths the developer wrote in code but the app didn't use during your session.
    * Right-click a Red Node -> Send to Repeater to test for IDORs, broken access control, or information disclosure.

## How it Works
The extension registers a HttpHandler via the Montoya API that inspects HTTP responses. If the response MIME type implies a script (JavaScript), it runs a regex pattern to find strings looking like API paths. It then compares these findings against live traffic to assign a status (Shadow vs. Verified).

The extension uses that exact same list of regular expressions in two different places:
1.
For Live Traffic (HTTP History): In the handleHttpRequestToBeSent method, it takes the path of the outgoing request (e.g., /v3/users/123) and matches it against your combined regex pattern. This is for discovering and verifying endpoints from live requests.
2.
For File Content (Scanning .js files): In the handleHttpResponseReceived method, it specifically checks if a response looks like a JavaScript file. If it does, it takes the entire text content of that file and runs the exact same combined regex pattern over it to find endpoint definitions like "/api/delete/".

## Customization
The current regex used to discover endpoints is:
```bash
['"]?(\/api\/[a-zA-Z0-9_\-\/{}]+)['"]?
['"]?(\/v1\/[a-zA-Z0-9_\-\/{}]+)['"]?
['"]?(\/v2\/[a-zA-Z0-9_\-\/{}]+)['"]?
['"]?(\/v3\/[a-zA-Z0-9_\-\/{}]+)['"]?
['"]?(\/v4\/[a-zA-Z0-9_\-\/{}]+)['"]?
['"]?(\/v5\/[a-zA-Z0-9_\-\/{}]+)['"]?
['"]?(\/v6\/[a-zA-Z0-9_\-\/{}]+)['"]?
['"]?(\/graphql[a-zA-Z0-9_\-\/]*)['"]?
```

https://github.com/user-attachments/assets/41c4552b-6bdf-468b-8b5d-e42bf8602c35

You can modify the apiPattern variable in ShadowApiVisualizer.java to customize this pattern for specific targets.
