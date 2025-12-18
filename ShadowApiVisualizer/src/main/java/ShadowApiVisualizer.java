import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;

import javax.swing.*;
import javax.swing.tree.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ShadowApiVisualizer implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Shadow API Visualizer");

        // --- DATA STRUCTURES ---
        // Map to keep track of unique paths and their nodes (for deduplication and updating)
        Map<String, DefaultMutableTreeNode> nodeMap = new ConcurrentHashMap<>();

        // --- UI COMPONENTS ---
        DefaultMutableTreeNode root = new DefaultMutableTreeNode("API Target (Root)");
        DefaultTreeModel treeModel = new DefaultTreeModel(root);
        JTree apiTree = new JTree(treeModel);

        // FEATURE 2: Custom Renderer for Color Coding
        apiTree.setCellRenderer(new ShadowRenderer());

        HttpRequestEditor requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        JTextArea responseArea = new JTextArea();
        responseArea.setEditable(false);
        responseArea.setFont(new Font("Monospaced", Font.PLAIN, 12));

        JTabbedPane editorsTab = new JTabbedPane();
        editorsTab.addTab("Request", requestEditor.uiComponent());
        editorsTab.addTab("Found In (Source)", new JScrollPane(responseArea));

        // --- FEATURE 3: CONTEXT MENU (Right Click) ---
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem copyItem = new JMenuItem("Copy Path");
        JMenuItem sendRepeaterItem = new JMenuItem("Send Request to Repeater");

        popupMenu.add(copyItem);
        popupMenu.add(sendRepeaterItem);

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

        // Context Menu Actions
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
                // Send the ORIGINAL request where we found the JS file, but ideally you'd want to construct a NEW request to the shadow endpoint.
                // For now, let's send the traffic where we found it, so the user can analyze context.
                api.repeater().sendToRepeater(finding.requestResponse.request(), "Shadow Finding");
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

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(apiTree), editorsTab);
        splitPane.setDividerLocation(300);
        api.userInterface().registerSuiteTab("Shadow Visualizer", splitPane);

        // Register Watcher
        api.http().registerHttpHandler(new TrafficWatcher(api, root, treeModel, nodeMap));
        api.logging().logToOutput("Shadow API Visualizer: Deduplication & Context Menus Active!");
    }
}

// --- CUSTOM CLASSES ---

// 1. Data Object
class ShadowFinding {
    public String path;
    public HttpRequestResponse requestResponse;
    public int start;
    public int end;
    public boolean isLive; // New: Tracks if we have seen this in real traffic

    public ShadowFinding(String path, HttpRequestResponse requestResponse, int start, int end) {
        this.path = path;
        this.requestResponse = requestResponse;
        this.start = start;
        this.end = end;
        this.isLive = false; // Default to Shadow (Red)
    }

    @Override
    public String toString() {
        return path + (isLive ? " [Verified]" : " [Shadow]");
    }
}

// 2. Custom Renderer (Colors)
class ShadowRenderer extends DefaultTreeCellRenderer {
    @Override
    public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel, boolean expanded, boolean leaf, int row, boolean hasFocus) {
        super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);

        DefaultMutableTreeNode node = (DefaultMutableTreeNode) value;
        if (node.getUserObject() instanceof ShadowFinding) {
            ShadowFinding finding = (ShadowFinding) node.getUserObject();
            if (finding.isLive) {
                setForeground(new Color(0, 128, 0)); // Green for Verified/Live
            } else {
                setForeground(Color.RED); // Red for Shadow/Hidden
            }
        }
        return this;
    }
}

// 3. Traffic Watcher
class TrafficWatcher implements HttpHandler {

    private final Logging logging;
    private final Pattern apiPattern = Pattern.compile("['\"](\\/api\\/[a-zA-Z0-9_\\-/]+|\\/v1\\/[a-zA-Z0-9_\\-/]+)['\"]");

    private final DefaultMutableTreeNode rootNode;
    private final DefaultTreeModel treeModel;
    private final Map<String, DefaultMutableTreeNode> nodeMap; // For Deduplication

    public TrafficWatcher(MontoyaApi api, DefaultMutableTreeNode rootNode, DefaultTreeModel treeModel, Map<String, DefaultMutableTreeNode> nodeMap) {
        this.logging = api.logging();
        this.rootNode = rootNode;
        this.treeModel = treeModel;
        this.nodeMap = nodeMap;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // Feature 2 Logic: Check if we are visiting a path that is in our tree
        String currentPath = requestToBeSent.path();

        if (nodeMap.containsKey(currentPath)) {
            DefaultMutableTreeNode node = nodeMap.get(currentPath);
            ShadowFinding finding = (ShadowFinding) node.getUserObject();

            if (!finding.isLive) {
                finding.isLive = true; // Mark as Verified

                // Update the UI
                SwingUtilities.invokeLater(() -> treeModel.nodeChanged(node));
                logging.logToOutput("[*] Verified Shadow API: " + currentPath);
            }
        }
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        boolean isJS = responseReceived.inferredMimeType().name().contains("SCRIPT") ||
                responseReceived.bodyToString().contains("function ");

        if (isJS) {
            String body = responseReceived.bodyToString();
            Matcher matcher = apiPattern.matcher(body);

            while (matcher.find()) {
                String foundPath = matcher.group(1);

                // Feature 1: Deduplication
                if (nodeMap.containsKey(foundPath)) {
                    continue; // Skip if we already found this
                }

                int start = matcher.start(1);
                int end = matcher.end(1);

                HttpRequestResponse storedTraffic = HttpRequestResponse.httpRequestResponse(
                        responseReceived.initiatingRequest(),
                        responseReceived
                );

                SwingUtilities.invokeLater(() -> {
                    // Double check inside UI thread to be safe
                    if (!nodeMap.containsKey(foundPath)) {
                        ShadowFinding finding = new ShadowFinding(foundPath, storedTraffic, start, end);
                        DefaultMutableTreeNode newNode = new DefaultMutableTreeNode(finding);

                        nodeMap.put(foundPath, newNode); // Add to deduplication map
                        rootNode.add(newNode);
                        treeModel.reload();
                    }
                });

                logging.logToOutput("[+] Found New Shadow API: " + foundPath);
            }
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }
}