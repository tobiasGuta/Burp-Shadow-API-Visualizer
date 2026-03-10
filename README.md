# Shadow API Visualizer (Burp Suite Extension)

![Java](https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=java&logoColor=white) ![Burp Suite](https://img.shields.io/badge/Burp_Suite-FF6633?style=for-the-badge&logo=burpsuite&logoColor=white) ![Security](https://img.shields.io/badge/Cybersecurity-Bug_Bounty-red?style=for-the-badge)


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
* **3-State Endpoint Tracking:**
    * **Red Nodes (Untested):** Endpoints found in code that you haven't tested yet. These are your priority targets.
    * **Orange Nodes (Tested):** Endpoints you've manually tested (sent to Repeater or marked as tested).
    * **Green Nodes (Verified):** Endpoints that have been actively visited in live browser traffic.
* **Testing Workflow:**
    * Right-click → "Send to Repeater" automatically marks the endpoint as tested.
    * Right-click → "Mark as Tested" / "Mark as Untested" for manual tracking.
    * **Export Untested** button to get a list of endpoints you still need to test.
    * **Status Filter** dropdown to show only Untested/Tested/Verified endpoints.
* **Source Code Highlighting:** Click any node to see the exact line of JavaScript where the endpoint was defined, highlighted automatically in the response viewer.
* **Workflow Integration:** Right-click any finding to "Send to Repeater" or "Copy URL".
* **Smart Deduplication:** Filters out duplicate findings to keep the workspace clean.
* **Expanded Detection:** Detects endpoints from `/api/`, `/admin/`, `/internal/`, `/debug/`, `/private/`, `/rest/`, `/auth/`, `/graphql`, and many more patterns.

## Installation

### Requirements
* Burp Suite Professional or Community Edition
* Java 17+ (or compatible JDK)

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
    * Focus on **Red Nodes (Untested)**. These are paths the developer wrote in code that you haven't tested yet.
    * Right-click a Red Node → **Send to Repeater** to test for IDORs, broken access control, or information disclosure.
    * The endpoint automatically turns **Orange (Tested)** when sent to Repeater.
5. Track Your Progress:
    * Use the **Status Filter** dropdown to show only "Untested Only" to see remaining work.
    * Click **Export Untested** to copy all untested paths to clipboard for use with other tools.
    * Manually mark endpoints as tested/untested via right-click menu.

## How it Works
The extension registers a HttpHandler via the Montoya API that inspects HTTP responses. If the response MIME type implies a script (JavaScript), it runs a regex pattern to find strings looking like API paths. It then tracks each endpoint through three states:
* **Untested (Red):** Found in code, not yet tested by you
* **Tested (Orange):** You've sent it to Repeater or manually marked it
* **Verified (Green):** The browser actually requested this endpoint during your session

The extension uses that exact same list of regular expressions in two different places:
1.
For Live Traffic (HTTP History): In the handleHttpRequestToBeSent method, it takes the path of the outgoing request (e.g., /v3/users/123) and matches it against your combined regex pattern. This is for discovering and verifying endpoints from live requests.
2.
For File Content (Scanning .js files): In the handleHttpResponseReceived method, it specifically checks if a response looks like a JavaScript file. If it does, it takes the entire text content of that file and runs the exact same combined regex pattern over it to find endpoint definitions like "/api/delete/".

## Customization

The default regex patterns can be customized directly within Burp Suite.

1. Go to the **Shadow Visualizer** tab.
2. Click on the **Settings** sub-tab.
3. Modify the patterns in the text area (one per line).
4. Click **"Update Regex"** to apply your changes instantly.

The current regex used to discover endpoints is:
```bash
['"](?\/api\/[a-zA-Z0-9_\-\/{}:]+)['"]?
['"](?\/v[0-9]+\/[a-zA-Z0-9_\-\/{}:]+)['"]?
['"](?\/graphql[a-zA-Z0-9_\-\/]*)['"]?
['"](?\/rest\/[a-zA-Z0-9_\-\/{}:]+)['"]?
['"](?\/internal\/[a-zA-Z0-9_\-\/{}:]+)['"]?
['"](?\/admin\/[a-zA-Z0-9_\-\/{}:]+)['"]?
['"](?\/debug\/[a-zA-Z0-9_\-\/{}:]+)['"]?
['"](?\/private\/[a-zA-Z0-9_\-\/{}:]+)['"]?
['"](?\/backend\/[a-zA-Z0-9_\-\/{}:]+)['"]?
['"](?\/service\/[a-zA-Z0-9_\-\/{}:]+)['"]?
['"](?\/services\/[a-zA-Z0-9_\-\/{}:]+)['"]?
['"](?\/auth\/[a-zA-Z0-9_\-\/{}:]+)['"]?
['"](?\/oauth\/[a-zA-Z0-9_\-\/{}:]+)['"]?
['"](?\/users\/[a-zA-Z0-9_\-\/{}:]+)['"]?
['"](?\/account[s]?\/[a-zA-Z0-9_\-\/{}:]+)['"]?
['"](?\/webhooks?\/[a-zA-Z0-9_\-\/{}:]+)['"]?
['"](?\/callback[s]?\/[a-zA-Z0-9_\-\/{}:]+)['"]?
['"](?\/config\/[a-zA-Z0-9_\-\/{}:]+)['"]?
['"](?\/settings\/[a-zA-Z0-9_\-\/{}:]+)['"]?
['"](?\/export\/[a-zA-Z0-9_\-\/{}:]+)['"]?
['"](?\/import\/[a-zA-Z0-9_\-\/{}:]+)['"]?
['"](?\/upload[s]?\/[a-zA-Z0-9_\-\/{}:]+)['"]?
['"](?\/download[s]?\/[a-zA-Z0-9_\-\/{}:]+)['"]?
['"](?\/[a-zA-Z0-9_\-]+\.json)['"]?
```

https://github.com/user-attachments/assets/41c4552b-6bdf-468b-8b5d-e42bf8602c35

Disclaimer
----------

This tool is for educational purposes and authorized security testing only. Do not use this tool on systems you do not have permission to test. The author is not responsible for any misuse.
---

<div align="center">
  <h3>☕ Support My Journey</h3>
</div>


<div align="center">
  <a href="https://www.buymeacoffee.com/tobiasguta">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" width="200" />
  </a>
</div>
