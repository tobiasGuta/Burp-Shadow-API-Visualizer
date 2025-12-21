import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;

import javax.swing.*;
import javax.swing.tree.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class ShadowApiVisualizer implements BurpExtension {

    private MontoyaApi api;
    private ShadowSettings settings;
    private Map<String, DefaultMutableTreeNode> nodeMap;
    private DefaultTreeModel treeModel;
    private DefaultMutableTreeNode root;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Shadow API Visualizer");

        // --- DATA & SETTINGS ---
        nodeMap = new ConcurrentHashMap<>();
        settings = new ShadowSettings();

        // --- UI COMPONENTS ---
        root = new DefaultMutableTreeNode("API Target (Root)");
        treeModel = new DefaultTreeModel(root);
        JTree apiTree = new JTree(treeModel);
        apiTree.setCellRenderer(new ShadowRenderer());

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
                nodeMap.remove(finding.path);
                treeModel.removeNodeFromParent(node);
            }
        });

        // --- SELECTION LISTENER ---
        apiTree.addTreeSelectionListener(e -> {
            DefaultMutableTreeNode selectedNode = (DefaultMutableTreeNode) apiTree.getLastSelectedPathComponent();
            if (selectedNode != null && selectedNode.getUserObject() instanceof ShadowFinding) {
                ShadowFinding finding = (ShadowFinding) selectedNode.getUserObject();
                requestEditor.setRequest(finding.requestResponse.request());
                responseArea.setText(finding.requestResponse.response().bodyToString());
                editorsTab.setSelectedIndex(1);
                try {
                    responseArea.setCaretPosition(finding.start);
                    responseArea.moveCaretPosition(finding.end);
                    responseArea.requestFocusInWindow();
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
        
        exportBtn.addActionListener(e -> {
            String result = nodeMap.keySet().stream().collect(Collectors.joining("\n"));
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(result), null);
            JOptionPane.showMessageDialog(dashboardPanel, "Copied " + nodeMap.size() + " paths to clipboard.");
        });
        
        clearBtn.addActionListener(e -> {
            nodeMap.clear();
            root.removeAllChildren();
            treeModel.reload();
        });

        toolBar.add(exportBtn);
        toolBar.add(clearBtn);
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
        api.http().registerHttpHandler(new TrafficWatcher(api, root, treeModel, nodeMap, settings));
        api.logging().logToOutput("Shadow API Visualizer: Enhanced Version Loaded!");
    }
}

// --- SETTINGS CLASS ---
class ShadowSettings {
    public boolean scopeOnly = false;
    public List<String> regexList = new ArrayList<>();
    public Pattern combinedPattern;

    public ShadowSettings() {
        // Default Regex
        regexList.add("['\"](\\/api\\/[a-zA-Z0-9_\\-\\/{}]+)['\"]");
        regexList.add("['\"](\\/v1\\/[a-zA-Z0-9_\\-\\/{}]+)['\"]");
        regexList.add("['\"](\\/graphql[a-zA-Z0-9_\\-\\/]*)['\"]");
        updateRegex(String.join("\n", regexList));
    }

    public void updateRegex(String text) {
        regexList.clear();
        List<String> parts = new ArrayList<>();
        for (String line : text.split("\n")) {
            if (!line.trim().isEmpty()) {
                regexList.add(line.trim());
                // Extract the inner group if possible, or just use the line
                // We assume the user provides a regex that captures the path in group 1
                // If they provide a simple string, we might need to wrap it, but let's trust the user or default
                parts.add(line.trim());
            }
        }
        // Combine into one pattern with OR
        String combined = String.join("|", parts);
        try {
            combinedPattern = Pattern.compile(combined);
        } catch (Exception e) {
            // Fallback
            combinedPattern = Pattern.compile("['\"](\\/api\\/[a-zA-Z0-9_\\-/]+)['\"]");
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

// --- CUSTOM RENDERER ---
class ShadowRenderer extends DefaultTreeCellRenderer {
    @Override
    public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel, boolean expanded, boolean leaf, int row, boolean hasFocus) {
        super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);

        DefaultMutableTreeNode node = (DefaultMutableTreeNode) value;
        if (node.getUserObject() instanceof ShadowFinding) {
            ShadowFinding finding = (ShadowFinding) node.getUserObject();
            if (finding.isLive) {
                setForeground(new Color(0, 128, 0)); // Green
            } else {
                setForeground(Color.RED); // Red
            }
            
            // Optional: Add icon based on method?
            // For now, text color is sufficient.
        }
        return this;
    }
}

// --- TRAFFIC WATCHER ---
class TrafficWatcher implements HttpHandler {

    private final MontoyaApi api;
    private final Logging logging;
    private final DefaultMutableTreeNode rootNode;
    private final DefaultTreeModel treeModel;
    private final Map<String, DefaultMutableTreeNode> nodeMap;
    private final ShadowSettings settings;

    public TrafficWatcher(MontoyaApi api, DefaultMutableTreeNode rootNode, DefaultTreeModel treeModel, Map<String, DefaultMutableTreeNode> nodeMap, ShadowSettings settings) {
        this.api = api;
        this.logging = api.logging();
        this.rootNode = rootNode;
        this.treeModel = treeModel;
        this.nodeMap = nodeMap;
        this.settings = settings;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // Feature: Live Verification
        String currentPath = requestToBeSent.path();

        if (nodeMap.containsKey(currentPath)) {
            DefaultMutableTreeNode node = nodeMap.get(currentPath);
            ShadowFinding finding = (ShadowFinding) node.getUserObject();

            if (!finding.isLive) {
                finding.isLive = true;
                SwingUtilities.invokeLater(() -> treeModel.nodeChanged(node));
                logging.logToOutput("[*] Verified Shadow API: " + currentPath);
            }
        }
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        // Feature: Scope Check
        if (settings.scopeOnly && !api.scope().isInScope(responseReceived.initiatingRequest().url())) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        boolean isJS = responseReceived.inferredMimeType().name().contains("SCRIPT") ||
                responseReceived.bodyToString().contains("function ") || 
                responseReceived.bodyToString().contains("const ");

        if (isJS) {
            String body = responseReceived.bodyToString();
            Matcher matcher = settings.combinedPattern.matcher(body);

            while (matcher.find()) {
                // We assume the path is in the first capturing group
                String foundPath = matcher.groupCount() >= 1 ? matcher.group(1) : matcher.group();

                if (nodeMap.containsKey(foundPath)) {
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

                SwingUtilities.invokeLater(() -> {
                    if (!nodeMap.containsKey(foundPath)) {
                        ShadowFinding finding = new ShadowFinding(foundPath, method, storedTraffic, start, end);
                        DefaultMutableTreeNode newNode = new DefaultMutableTreeNode(finding);

                        nodeMap.put(foundPath, newNode);
                        rootNode.add(newNode);
                        treeModel.reload();
                        
                        // Feature: Burp Issue (Best Effort)
                        // We can't easily add issues to the dashboard from HttpHandler in Montoya without ScanCheck
                        // But we can log it.
                    }
                });
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
