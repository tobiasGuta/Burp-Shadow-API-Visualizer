import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.tree.*;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class ShadowApiVisualizer implements BurpExtension {

    private MontoyaApi api;
    private ShadowSettings settings;
    private Map<String, DefaultMutableTreeNode> nodeMap; // Key: Host + "::" + Path
    private Map<String, DefaultMutableTreeNode> hostNodeMap; // Key: Host
    private DefaultTreeModel treeModel;
    private DefaultMutableTreeNode root;
    private JTree apiTree;
    private String filterText = "";
    private JLabel statusLabel;
    private ExecutorService saveExecutor;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Shadow API Visualizer");

        // --- DATA & SETTINGS ---
        nodeMap = new ConcurrentHashMap<>();
        hostNodeMap = new ConcurrentHashMap<>();
        settings = new ShadowSettings();
        saveExecutor = Executors.newSingleThreadExecutor();

        // --- UI COMPONENTS ---
        root = new DefaultMutableTreeNode("API Target (Root)");
        treeModel = new DefaultTreeModel(root);
        apiTree = new JTree(treeModel);
        apiTree.setCellRenderer(new ShadowRenderer());
        apiTree.setRootVisible(true);
        apiTree.setShowsRootHandles(true);

        HttpRequestEditor requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        JTextArea responseArea = new JTextArea();
        responseArea.setEditable(false);
        responseArea.setFont(new Font("Monospaced", Font.PLAIN, 12));

        JTabbedPane editorsTab = new JTabbedPane();
        editorsTab.addTab("Request", requestEditor.uiComponent());
        editorsTab.addTab("Found In (Source)", new JScrollPane(responseArea));

        // --- CONTEXT MENU ---
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem copyItem = new JMenuItem("Copy Path");
        JMenuItem sendRepeaterItem = new JMenuItem("Send Request to Repeater");
        JMenuItem deleteItem = new JMenuItem("Delete / Ignore");

        popupMenu.add(copyItem);
        popupMenu.add(sendRepeaterItem);
        popupMenu.addSeparator();
        popupMenu.add(deleteItem);

        apiTree.addMouseListener(new MouseAdapter() {
            public void mousePressed(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    int row = apiTree.getClosestRowForLocation(e.getX(), e.getY());
                    apiTree.setSelectionRow(row);
                    DefaultMutableTreeNode node = (DefaultMutableTreeNode) apiTree.getLastSelectedPathComponent();
                    if (node != null && node.getUserObject() instanceof ShadowFinding) {
                        popupMenu.show(e.getComponent(), e.getX(), e.getY());
                    }
                }
            }
        });

        copyItem.addActionListener(e -> {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) apiTree.getLastSelectedPathComponent();
            if (node != null && node.getUserObject() instanceof ShadowFinding) {
                ShadowFinding finding = (ShadowFinding) node.getUserObject();
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(finding.path), null);
            }
        });

        sendRepeaterItem.addActionListener(e -> {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) apiTree.getLastSelectedPathComponent();
            if (node != null && node.getUserObject() instanceof ShadowFinding) {
                ShadowFinding finding = (ShadowFinding) node.getUserObject();
                api.repeater().sendToRepeater(finding.requestResponse.request(), "Shadow Finding");
            }
        });

        deleteItem.addActionListener(e -> {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) apiTree.getLastSelectedPathComponent();
            if (node != null && node.getUserObject() instanceof ShadowFinding) {
                ShadowFinding finding = (ShadowFinding) node.getUserObject();
                String host = finding.requestResponse.request().httpService().host();
                String key = host + "::" + finding.path;
                nodeMap.remove(key);
                treeModel.removeNodeFromParent(node);
                saveSession();
            }
        });

        // --- SELECTION LISTENER ---
        apiTree.addTreeSelectionListener(e -> {
            DefaultMutableTreeNode selectedNode = (DefaultMutableTreeNode) apiTree.getLastSelectedPathComponent();
            if (selectedNode != null && selectedNode.getUserObject() instanceof ShadowFinding) {
                ShadowFinding finding = (ShadowFinding) selectedNode.getUserObject();
                requestEditor.setRequest(finding.requestResponse.request());
                if (finding.requestResponse.response() != null) {
                    responseArea.setText(finding.requestResponse.response().bodyToString());
                } else {
                    responseArea.setText("");
                }
                editorsTab.setSelectedIndex(1);
                
                // Highlight Logic
                Highlighter highlighter = responseArea.getHighlighter();
                highlighter.removeAllHighlights();
                try {
                    responseArea.setCaretPosition(finding.start);
                    responseArea.moveCaretPosition(finding.end);
                    responseArea.requestFocusInWindow();
                    
                    // Adaptive Highlight Color
                    Color bg = responseArea.getBackground();
                    boolean isDark = (bg.getRed() + bg.getGreen() + bg.getBlue()) / 3 < 128;
                    Color highlightColor = isDark ? new Color(139, 128, 0) : Color.YELLOW; // Dark Goldenrod for dark mode

                    highlighter.addHighlight(finding.start, finding.end, new DefaultHighlighter.DefaultHighlightPainter(highlightColor));
                } catch (Exception ex) { /* Ignore range errors */ }
            }
        });

        // --- DASHBOARD PANEL ---
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(apiTree), editorsTab);
        splitPane.setDividerLocation(300);

        JPanel dashboardPanel = new JPanel(new BorderLayout());
        JToolBar toolBar = new JToolBar();
        JButton exportBtn = new JButton("Export All to Clipboard");
        JButton clearBtn = new JButton("Clear All");
        
        // Search Bar
        JTextField searchField = new JTextField(20);
        searchField.setToolTipText("Filter endpoints...");
        // Add a placeholder-like effect using border title or just a label
        // Using a simple label in toolbar for clarity
        JLabel searchLabel = new JLabel(" Filter: ");
        
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { applyFilter(searchField.getText()); }
            @Override
            public void removeUpdate(DocumentEvent e) { applyFilter(searchField.getText()); }
            @Override
            public void changedUpdate(DocumentEvent e) { applyFilter(searchField.getText()); }
        });

        exportBtn.addActionListener(e -> {
            String result = nodeMap.values().stream()
                    .map(node -> ((ShadowFinding) node.getUserObject()).path)
                    .collect(Collectors.joining("\n"));
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(result), null);
            JOptionPane.showMessageDialog(dashboardPanel, "Copied " + nodeMap.size() + " paths to clipboard.");
        });
        
        clearBtn.addActionListener(e -> {
            nodeMap.clear();
            hostNodeMap.clear();
            root.removeAllChildren();
            treeModel.reload();
            api.persistence().extensionData().deleteString("shadow_session");
            statusLabel.setText("Project Cleared");
        });

        statusLabel = new JLabel("Project Synced");
        statusLabel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 0));

        toolBar.add(exportBtn);
        toolBar.add(clearBtn);
        toolBar.addSeparator();
        toolBar.add(searchLabel);
        toolBar.add(searchField);
        toolBar.add(Box.createHorizontalGlue());
        toolBar.add(statusLabel);
        
        dashboardPanel.add(toolBar, BorderLayout.NORTH);
        dashboardPanel.add(splitPane, BorderLayout.CENTER);

        // --- SETTINGS PANEL ---
        JPanel settingsPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridx = 0; gbc.gridy = 0;
        
        JCheckBox scopeOnlyCheck = new JCheckBox("Only Analyze In-Scope Traffic", settings.scopeOnly);
        scopeOnlyCheck.addActionListener(e -> settings.scopeOnly = scopeOnlyCheck.isSelected());
        settingsPanel.add(scopeOnlyCheck, gbc);

        gbc.gridy++;
        settingsPanel.add(new JLabel("Regex Pattern (One per line):"), gbc);
        
        gbc.gridy++;
        JTextArea regexArea = new JTextArea(10, 40);
        regexArea.setText(String.join("\n", settings.regexList));
        settingsPanel.add(new JScrollPane(regexArea), gbc);

        gbc.gridy++;
        JButton saveSettingsBtn = new JButton("Update Regex");
        saveSettingsBtn.addActionListener(e -> {
            settings.updateRegex(regexArea.getText());
            JOptionPane.showMessageDialog(settingsPanel, "Regex Updated!");
        });
        settingsPanel.add(saveSettingsBtn, gbc);

        // --- MAIN TABS ---
        JTabbedPane mainTabs = new JTabbedPane();
        mainTabs.addTab("Dashboard", dashboardPanel);
        mainTabs.addTab("Settings", settingsPanel);

        api.userInterface().registerSuiteTab("Shadow Visualizer", mainTabs);

        // Register Watcher
        api.http().registerHttpHandler(new TrafficWatcher());
        api.logging().logToOutput("Shadow API Visualizer: Enhanced Version Loaded!");

        // Restore Session
        restoreSession();
    }

    private void applyFilter(String text) {
        this.filterText = text.trim().toLowerCase();
        root.removeAllChildren();

        // Group findings by host
        Map<String, List<DefaultMutableTreeNode>> findingsByHost = new HashMap<>();
        for (DefaultMutableTreeNode node : nodeMap.values()) {
            ShadowFinding finding = (ShadowFinding) node.getUserObject();
            String host = finding.requestResponse.request().httpService().host();
            findingsByHost.computeIfAbsent(host, k -> new ArrayList<>()).add(node);
        }

        for (String host : hostNodeMap.keySet()) {
            DefaultMutableTreeNode hostNode = hostNodeMap.get(host);
            hostNode.removeAllChildren(); // Clear current view

            boolean hostMatches = host.toLowerCase().contains(filterText);
            List<DefaultMutableTreeNode> findings = findingsByHost.get(host);
            boolean hasVisibleChildren = false;

            if (findings != null) {
                for (DefaultMutableTreeNode findingNode : findings) {
                    ShadowFinding finding = (ShadowFinding) findingNode.getUserObject();
                    boolean findingMatches = finding.path.toLowerCase().contains(filterText);

                    if (hostMatches || findingMatches) {
                        hostNode.add(findingNode);
                        hasVisibleChildren = true;
                    }
                }
            }

            if (hostMatches || hasVisibleChildren) {
                root.add(hostNode);
            }
        }

        treeModel.reload();

        if (!filterText.isEmpty()) {
            for (int i = 0; i < apiTree.getRowCount(); i++) {
                apiTree.expandRow(i);
            }
        }
    }

    private boolean isVisible(String host, String path) {
        if (filterText.isEmpty()) return true;
        return host.toLowerCase().contains(filterText) || path.toLowerCase().contains(filterText);
    }

    private DefaultMutableTreeNode getOrCreateHostNode(String host) {
        if (host == null || host.isEmpty()) host = "Unknown Host";
        
        if (hostNodeMap.containsKey(host)) return hostNodeMap.get(host);
        
        DefaultMutableTreeNode node = new DefaultMutableTreeNode(host);
        hostNodeMap.put(host, node);
        return node;
    }

    private void saveSession() {
        saveExecutor.submit(() -> {
            try {
                List<ShadowFindingDTO> dtos = new ArrayList<>();
                for (DefaultMutableTreeNode node : nodeMap.values()) {
                    if (node.getUserObject() instanceof ShadowFinding) {
                        dtos.add(new ShadowFindingDTO((ShadowFinding) node.getUserObject()));
                    }
                }
                String json = new Gson().toJson(dtos);
                api.persistence().extensionData().setString("shadow_session", json);
                SwingUtilities.invokeLater(() -> statusLabel.setText("Last Saved: " + java.time.LocalTime.now().toString()));
            } catch (Exception e) {
                api.logging().logToError("Failed to save session: " + e.getMessage());
            }
        });
    }

    private void restoreSession() {
        String json = api.persistence().extensionData().getString("shadow_session");
        if (json != null && !json.isEmpty()) {
            try {
                Type listType = new TypeToken<ArrayList<ShadowFindingDTO>>(){}.getType();
                List<ShadowFindingDTO> dtos = new Gson().fromJson(json, listType);
                
                for (ShadowFindingDTO dto : dtos) {
                    ShadowFinding finding = dto.toShadowFinding(api);
                    String host = finding.requestResponse.request().httpService().host();
                    String key = host + "::" + finding.path;
                    
                    DefaultMutableTreeNode newNode = new DefaultMutableTreeNode(finding);
                    nodeMap.put(key, newNode);
                    
                    DefaultMutableTreeNode hostNode = getOrCreateHostNode(host);
                    if (hostNode.getParent() == null) {
                        root.add(hostNode);
                    }
                    hostNode.add(newNode);
                }
                treeModel.reload();
                api.logging().logToOutput("Restored " + dtos.size() + " findings from previous session.");
            } catch (Exception e) {
                api.logging().logToError("Failed to restore session: " + e.getMessage());
            }
        }
    }

    // --- TRAFFIC WATCHER ---
    class TrafficWatcher implements HttpHandler {

        private String getFoundPath(Matcher matcher) {
            if (matcher.groupCount() > 0) {
                for (int i = 1; i <= matcher.groupCount(); i++) {
                    if (matcher.group(i) != null) {
                        return matcher.group(i);
                    }
                }
            }
            return matcher.group();
        }

        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
            String currentPath = requestToBeSent.path();
            String host = requestToBeSent.httpService().host();
            String key = host + "::" + currentPath;

            // Feature: Live Verification
            if (nodeMap.containsKey(key)) {
                DefaultMutableTreeNode node = nodeMap.get(key);
                ShadowFinding finding = (ShadowFinding) node.getUserObject();

                if (!finding.isLive) {
                    finding.isLive = true;
                    SwingUtilities.invokeLater(() -> treeModel.nodeChanged(node));
                    api.logging().logToOutput("[*] Verified Shadow API: " + currentPath);
                    saveSession();
                }
            } else {
                // Feature: Live API Discovery
                if (settings.scopeOnly && !api.scope().isInScope(requestToBeSent.url())) {
                    return RequestToBeSentAction.continueWith(requestToBeSent);
                }

                Matcher matcher = settings.combinedPattern.matcher(currentPath);
                if (matcher.find()) {
                    String foundPath = getFoundPath(matcher);
                    if (foundPath != null && !foundPath.isEmpty()) {
                        String foundKey = host + "::" + foundPath;
                        if (!nodeMap.containsKey(foundKey)) {
                            api.logging().logToOutput("[+] Discovered Live API: " + foundPath);
                            ShadowFinding finding = new ShadowFinding(foundPath, requestToBeSent.method(), HttpRequestResponse.httpRequestResponse(requestToBeSent, null), 0, 0);
                            finding.isLive = true;

                            DefaultMutableTreeNode newNode = new DefaultMutableTreeNode(finding);
                            nodeMap.put(foundKey, newNode);
                            
                            SwingUtilities.invokeLater(() -> {
                                if (isVisible(host, foundPath)) {
                                    DefaultMutableTreeNode hostNode = getOrCreateHostNode(host);
                                    if (hostNode.getParent() == null) {
                                        treeModel.insertNodeInto(hostNode, root, root.getChildCount());
                                    }
                                    treeModel.insertNodeInto(newNode, hostNode, hostNode.getChildCount());
                                    if (!filterText.isEmpty()) {
                                        apiTree.expandPath(new TreePath(hostNode.getPath()));
                                    }
                                }
                            });
                            saveSession();
                        }
                    }
                }
            }
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
            String requestPath = responseReceived.initiatingRequest().path();
            String host = responseReceived.initiatingRequest().httpService().host();
            String key = host + "::" + requestPath;

            // Feature: Update response for live-discovered APIs
            if (nodeMap.containsKey(key)) {
                DefaultMutableTreeNode node = nodeMap.get(key);
                ShadowFinding finding = (ShadowFinding) node.getUserObject();
                if (finding.requestResponse.response() == null) {
                    finding.requestResponse = HttpRequestResponse.httpRequestResponse(responseReceived.initiatingRequest(), responseReceived);
                    saveSession();
                }
            }

            // Feature: Scope Check for response analysis
            if (settings.scopeOnly && !api.scope().isInScope(responseReceived.initiatingRequest().url())) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }

            boolean isJS = responseReceived.inferredMimeType().name().contains("SCRIPT") ||
                    responseReceived.bodyToString().contains("function ") || 
                    responseReceived.bodyToString().contains("const ");

            if (isJS) {
                String body = responseReceived.bodyToString();
                
                // Optimization: Skip very large files to prevent regex freezing
                if (body.length() > 5000000) { // 5MB limit
                     return ResponseReceivedAction.continueWith(responseReceived);
                }
                
                Matcher matcher = settings.combinedPattern.matcher(body);

                while (matcher.find()) {
                    String foundPath = getFoundPath(matcher);

                    if (foundPath == null || foundPath.isEmpty()) {
                        continue;
                    }
                    
                    String foundKey = host + "::" + foundPath;
                    if (nodeMap.containsKey(foundKey)) {
                        continue;
                    }

                    int start = matcher.start();
                    int end = matcher.end();

                    // Feature: Method Inference
                    String method = inferMethod(body, start);

                    HttpRequestResponse storedTraffic = HttpRequestResponse.httpRequestResponse(
                            responseReceived.initiatingRequest(),
                            responseReceived
                    );

                    final String finalFoundPath = foundPath;
                    SwingUtilities.invokeLater(() -> {
                        if (!nodeMap.containsKey(foundKey)) {
                            ShadowFinding finding = new ShadowFinding(finalFoundPath, method, storedTraffic, start, end);
                            DefaultMutableTreeNode newNode = new DefaultMutableTreeNode(finding);

                            nodeMap.put(foundKey, newNode);
                            
                            if (isVisible(host, finalFoundPath)) {
                                DefaultMutableTreeNode hostNode = getOrCreateHostNode(host);
                                if (hostNode.getParent() == null) {
                                    treeModel.insertNodeInto(hostNode, root, root.getChildCount());
                                }
                                treeModel.insertNodeInto(newNode, hostNode, hostNode.getChildCount());
                                if (!filterText.isEmpty()) {
                                    apiTree.expandPath(new TreePath(hostNode.getPath()));
                                }
                            }
                        }
                    });
                    saveSession();
                }
            }
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        private String inferMethod(String body, int index) {
            // Look backwards 50 chars for keywords
            int lookBack = Math.max(0, index - 50);
            String context = body.substring(lookBack, index).toLowerCase();
            
            if (context.contains("post") || context.contains("axios.post")) return "POST";
            if (context.contains("get") || context.contains("axios.get")) return "GET";
            if (context.contains("put") || context.contains("axios.put")) return "PUT";
            if (context.contains("delete") || context.contains("axios.delete")) return "DELETE";
            
            return null; // Unknown
        }
    }
}

// --- SETTINGS CLASS ---
class ShadowSettings {
    public boolean scopeOnly = false;
    public List<String> regexList = new ArrayList<>();
    public Pattern combinedPattern;

    public ShadowSettings() {
        // Default Regex
        regexList.add("['\"]?(\\/api\\/[a-zA-Z0-9_\\-\\/{}]+)['\"]?");
        regexList.add("['\"]?(\\/v1\\/[a-zA-Z0-9_\\-\\/{}]+)['\"]?");
        regexList.add("['\"]?(\\/v2\\/[a-zA-Z0-9_\\-\\/{}]+)['\"]?");
        regexList.add("['\"]?(\\/v3\\/[a-zA-Z0-9_\\-\\/{}]+)['\"]?");
        regexList.add("['\"]?(\\/v4\\/[a-zA-Z0-9_\\-\\/{}]+)['\"]?");
        regexList.add("['\"]?(\\/v5\\/[a-zA-Z0-9_\\-\\/{}]+)['\"]?");
        regexList.add("['\"]?(\\/v6\\/[a-zA-Z0-9_\\-\\/{}]+)['\"]?");
        regexList.add("['\"]?(\\/graphql[a-zA-Z0-9_\\-\\/]*)['\"]?");
        updateRegex(String.join("\n", regexList));
    }

    public void updateRegex(String text) {
        regexList.clear();
        List<String> parts = new ArrayList<>();
        for (String line : text.split("\n")) {
            if (!line.trim().isEmpty()) {
                regexList.add(line.trim());
                parts.add(line.trim());
            }
        }
        // Combine into one pattern with OR
        String combined = String.join("|", parts);
        try {
            // Optimization: Case Insensitive
            combinedPattern = Pattern.compile(combined, Pattern.CASE_INSENSITIVE);
        } catch (Exception e) {
            // Fallback
            combinedPattern = Pattern.compile("['\"]?(\\/api\\/[a-zA-Z0-9_\\-/]+)['\"]?", Pattern.CASE_INSENSITIVE);
        }
    }
}

// --- DATA OBJECT ---
class ShadowFinding {
    public String path;
    public String method; // GET, POST, etc.
    public HttpRequestResponse requestResponse;
    public int start;
    public int end;
    public boolean isLive;

    public ShadowFinding(String path, String method, HttpRequestResponse requestResponse, int start, int end) {
        this.path = path;
        this.method = method;
        this.requestResponse = requestResponse;
        this.start = start;
        this.end = end;
        this.isLive = false;
    }

    @Override
    public String toString() {
        String prefix = method != null ? "[" + method + "] " : "";
        return prefix + path + (isLive ? " [Verified]" : " [Shadow]");
    }
}

// --- DTO FOR SERIALIZATION ---
class ShadowFindingDTO {
    public String path;
    public String method;
    public int start;
    public int end;
    public boolean isLive;
    public String requestBase64;
    public String responseBase64;
    public String host;
    public boolean isHttps;
    public int port;

    public ShadowFindingDTO(ShadowFinding finding) {
        this.path = finding.path;
        this.method = finding.method;
        this.start = finding.start;
        this.end = finding.end;
        this.isLive = finding.isLive;
        
        if (finding.requestResponse != null) {
            if (finding.requestResponse.request() != null) {
                this.requestBase64 = Base64.getEncoder().encodeToString(finding.requestResponse.request().toByteArray().getBytes());
                this.host = finding.requestResponse.request().httpService().host();
                this.isHttps = finding.requestResponse.request().httpService().secure();
                this.port = finding.requestResponse.request().httpService().port();
            }
            if (finding.requestResponse.response() != null) {
                this.responseBase64 = Base64.getEncoder().encodeToString(finding.requestResponse.response().toByteArray().getBytes());
            }
        }
    }

    public ShadowFinding toShadowFinding(MontoyaApi api) {
        HttpRequest request = null;
        HttpResponse response = null;

        if (requestBase64 != null) {
            request = HttpRequest.httpRequest(
                burp.api.montoya.http.HttpService.httpService(host, port, isHttps),
                ByteArray.byteArray(Base64.getDecoder().decode(requestBase64))
            );
        }
        if (responseBase64 != null) {
            response = HttpResponse.httpResponse(
                ByteArray.byteArray(Base64.getDecoder().decode(responseBase64))
            );
        }

        HttpRequestResponse rr = HttpRequestResponse.httpRequestResponse(request, response);
        ShadowFinding finding = new ShadowFinding(path, method, rr, start, end);
        finding.isLive = isLive;
        return finding;
    }
}

// --- CUSTOM RENDERER ---
class ShadowRenderer extends DefaultTreeCellRenderer {
    
    private final Icon hostIcon;
    private final Icon findingIcon;
    private final Icon rootIcon;

    public ShadowRenderer() {
        // Load standard Swing icons
        Icon folder = UIManager.getIcon("FileView.directoryIcon");
        Icon file = UIManager.getIcon("FileView.fileIcon");
        Icon computer = UIManager.getIcon("FileView.computerIcon");
        Icon drive = UIManager.getIcon("FileView.hardDriveIcon");
        
        // Use drive icon for Host if available, otherwise folder
        this.hostIcon = (drive != null) ? drive : folder;
        // Use file icon for findings
        this.findingIcon = file;
        this.rootIcon = (computer != null) ? computer : folder;
    }

    @Override
    public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel, boolean expanded, boolean leaf, int row, boolean hasFocus) {
        super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);

        DefaultMutableTreeNode node = (DefaultMutableTreeNode) value;
        Object userObject = node.getUserObject();

        if (userObject instanceof ShadowFinding) {
            ShadowFinding finding = (ShadowFinding) userObject;
            setIcon(findingIcon);
            
            if (finding.isLive) {
                setForeground(new Color(0, 128, 0)); // Dark Green
            } else {
                setForeground(new Color(180, 0, 0)); // Dark Red
            }
        } else if (node.getLevel() == 1) { 
            // Host Node
            setIcon(hostIcon);
            setText("🔒 " + userObject.toString());
            // Removed explicit setForeground(Color.BLACK) to allow theme adaptation
        } else if (node.isRoot()) {
            setIcon(rootIcon);
            // Removed explicit setForeground(Color.BLACK) to allow theme adaptation
        }

        return this;
    }
}
