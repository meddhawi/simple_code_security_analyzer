#include <iostream>
#include <string>
#include <vector>
#include <queue>
#include <stack>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <algorithm>
#include <ctime>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>

using namespace std;
using namespace std::chrono;

// Struktur untuk menyimpan log aktivitas (existing)
struct LogEntry {
    string timestamp;
    string ipAddress;
    string action;
    string status;
    int severity; // 1-10 (1=low, 10=critical)
    
    LogEntry(string ts = "", string ip = "", string act = "", string st = "", int sev = 1)
        : timestamp(ts), ipAddress(ip), action(act), status(st), severity(sev) {}
        
    void display() const {
        cout << "Timestamp: " << timestamp << ", IP: " << ipAddress 
             << ", Action: " << action << ", Status: " << status 
             << ", Severity: " << severity << endl;
    }
};

// Network Graph Implementation
class NetworkGraph {
private:
    // Adjacency list: IP -> vector of (connected_IP, weight)
    unordered_map<string, vector<pair<string, int>>> adjList;
    unordered_set<string> nodes;
    
public:
    // Add node to graph
    void addNode(const string& nodeId) {
        nodes.insert(nodeId);
        if (adjList.find(nodeId) == adjList.end()) {
            adjList[nodeId] = vector<pair<string, int>>();
        }
    }
    
    // Add edge between two nodes with weight
    void addEdge(const string& from, const string& to, int weight = 1) {
        addNode(from);
        addNode(to);
        
        // Add edge from -> to
        adjList[from].push_back({to, weight});
        
        // For undirected graph, add edge to -> from
        adjList[to].push_back({from, weight});
    }
    
    // Get neighbors of a node
    vector<pair<string, int>> getNeighbors(const string& nodeId) {
        if (adjList.find(nodeId) != adjList.end()) {
            return adjList[nodeId];
        }
        return {};
    }
    
    // Display graph
    void displayGraph() {
        cout << "\n=== Network Topology Graph ===" << endl;
        cout << "Total Nodes: " << nodes.size() << endl;
        cout << "Connections:" << endl;
        
        for (const auto& node : adjList) {
            cout << node.first << " -> ";
            for (const auto& neighbor : node.second) {
                cout << neighbor.first << "(w:" << neighbor.second << ") ";
            }
            cout << endl;
        }
    }
    
    // Get all nodes
    unordered_set<string> getAllNodes() {
        return nodes;
    }
    
    // Check if node exists
    bool hasNode(const string& nodeId) {
        return nodes.find(nodeId) != nodes.end();
    }
    
    // Get graph statistics
    void getGraphStats() {
        int totalEdges = 0;
        for (const auto& node : adjList) {
            totalEdges += node.second.size();
        }
        totalEdges /= 2; // Since it's undirected
        
        cout << "\n=== Graph Statistics ===" << endl;
        cout << "Total Nodes: " << nodes.size() << endl;
        cout << "Total Edges: " << totalEdges << endl;
        cout << "Average Degree: " << (nodes.size() > 0 ? (double)totalEdges * 2 / nodes.size() : 0) << endl;
    }
};

// BFS Analyzer Implementation
class BFSAnalyzer {
private:
    NetworkGraph* graph;
    
public:
    BFSAnalyzer(NetworkGraph* g) : graph(g) {}
    
    // BFS to find shortest path between two nodes
    vector<string> findShortestPath(const string& source, const string& target) {
        if (!graph->hasNode(source) || !graph->hasNode(target)) {
            return {};
        }
        
        queue<string> q;
        unordered_map<string, string> parent;
        unordered_set<string> visited;
        
        q.push(source);
        visited.insert(source);
        parent[source] = "";
        
        while (!q.empty()) {
            string current = q.front();
            q.pop();
            
            if (current == target) {
                // Reconstruct path
                vector<string> path;
                string node = target;
                while (node != "") {
                    path.push_back(node);
                    node = parent[node];
                }
                reverse(path.begin(), path.end());
                return path;
            }
            
            for (const auto& neighbor : graph->getNeighbors(current)) {
                if (visited.find(neighbor.first) == visited.end()) {
                    visited.insert(neighbor.first);
                    parent[neighbor.first] = current;
                    q.push(neighbor.first);
                }
            }
        }
        
        return {}; // No path found
    }
    
    // BFS to detect nodes within certain radius (for anomaly detection)
    vector<string> getNodesInRadius(const string& center, int radius) {
        vector<string> result;
        if (!graph->hasNode(center)) {
            return result;
        }
        
        queue<pair<string, int>> q; // (node, distance)
        unordered_set<string> visited;
        
        q.push({center, 0});
        visited.insert(center);
        
        while (!q.empty()) {
            auto [current, dist] = q.front();
            q.pop();
            
            if (dist <= radius) {
                result.push_back(current);
            }
            
            if (dist < radius) {
                for (const auto& neighbor : graph->getNeighbors(current)) {
                    if (visited.find(neighbor.first) == visited.end()) {
                        visited.insert(neighbor.first);
                        q.push({neighbor.first, dist + 1});
                    }
                }
            }
        }
        
        return result;
    }
    
    // BFS to map network layers
    map<int, vector<string>> mapNetworkLayers(const string& startNode) {
        map<int, vector<string>> layers;
        if (!graph->hasNode(startNode)) {
            return layers;
        }
        
        queue<pair<string, int>> q;
        unordered_set<string> visited;
        
        q.push({startNode, 0});
        visited.insert(startNode);
        
        while (!q.empty()) {
            auto [current, layer] = q.front();
            q.pop();
            
            layers[layer].push_back(current);
            
            for (const auto& neighbor : graph->getNeighbors(current)) {
                if (visited.find(neighbor.first) == visited.end()) {
                    visited.insert(neighbor.first);
                    q.push({neighbor.first, layer + 1});
                }
            }
        }
        
        return layers;
    }
};

// DFS Analyzer Implementation
class DFSAnalyzer {
private:
    NetworkGraph* graph;
    
    // DFS helper for cycle detection
    bool dfsHasCycle(const string& node, const string& parent, 
                     unordered_set<string>& visited, vector<string>& path) {
        visited.insert(node);
        path.push_back(node);
        
        for (const auto& neighbor : graph->getNeighbors(node)) {
            if (neighbor.first != parent) {
                if (visited.find(neighbor.first) != visited.end()) {
                    // Cycle detected
                    path.push_back(neighbor.first);
                    return true;
                }
                
                if (dfsHasCycle(neighbor.first, node, visited, path)) {
                    return true;
                }
            }
        }
        
        path.pop_back();
        return false;
    }
    
    // DFS helper for path tracing
    void dfsTracePath(const string& node, unordered_set<string>& visited, 
                      vector<string>& path, vector<vector<string>>& allPaths) {
        visited.insert(node);
        path.push_back(node);
        
        // Check if this is a potential endpoint (has fewer connections)
        if (graph->getNeighbors(node).size() <= 1 && path.size() > 1) {
            allPaths.push_back(path);
        }
        
        for (const auto& neighbor : graph->getNeighbors(node)) {
            if (visited.find(neighbor.first) == visited.end()) {
                dfsTracePath(neighbor.first, visited, path, allPaths);
            }
        }
        
        path.pop_back();
        visited.erase(node);
    }
    
public:
    DFSAnalyzer(NetworkGraph* g) : graph(g) {}
    
    // DFS to detect cycles in communication (potential backdoor)
    bool detectCommunicationCycle(const string& startNode, vector<string>& cyclePath) {
        if (!graph->hasNode(startNode)) {
            return false;
        }
        
        unordered_set<string> visited;
        cyclePath.clear();
        
        return dfsHasCycle(startNode, "", visited, cyclePath);
    }
    
    // DFS for comprehensive path tracing
    vector<vector<string>> traceAllPaths(const string& startNode) {
        vector<vector<string>> allPaths;
        if (!graph->hasNode(startNode)) {
            return allPaths;
        }
        
        unordered_set<string> visited;
        vector<string> currentPath;
        
        dfsTracePath(startNode, visited, currentPath, allPaths);
        
        return allPaths;
    }
    
    // DFS to assess vulnerability depth
    void assessVulnerabilityDepth(const string& targetNode) {
        if (!graph->hasNode(targetNode)) {
            cout << "Target node not found in graph." << endl;
            return;
        }
        
        cout << "\n=== Vulnerability Assessment for " << targetNode << " ===" << endl;
        
        auto allPaths = traceAllPaths(targetNode);
        
        cout << "Total possible attack paths: " << allPaths.size() << endl;
        cout << "Detailed paths:" << endl;
        
        for (size_t i = 0; i < allPaths.size(); i++) {
            cout << "Path " << i + 1 << ": ";
            for (size_t j = 0; j < allPaths[i].size(); j++) {
                cout << allPaths[i][j];
                if (j < allPaths[i].size() - 1) cout << " -> ";
            }
            cout << " (Length: " << allPaths[i].size() << ")" << endl;
        }
    }
};

// Big O Analyzer Implementation
class BigOAnalyzer {
private:
    vector<LogEntry>* logs;
    
    // Timer helper
    template<typename Func>
    double measureTime(Func func) {
        auto start = high_resolution_clock::now();
        func();
        auto end = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(end - start);
        return duration.count() / 1000.0; // Convert to milliseconds
    }
    
public:
    BigOAnalyzer(vector<LogEntry>* logArray) : logs(logArray) {}
    
    // Analyze complexity of different operations
    void analyzeComplexity() {
        if (logs->empty()) {
            cout << "No logs available for analysis." << endl;
            return;
        }
        
        cout << "\n=== Big O Complexity Analysis ===" << endl;
        cout << "Dataset size: " << logs->size() << " logs" << endl;
        
        // Linear Search - O(n)
        double linearTime = measureTime([this]() {
            for (int i = 0; i < 100; i++) {
                for (const auto& log : *logs) {
                    if (log.ipAddress == "192.168.1.1") break;
                }
            }
        });
        cout << "Linear Search (O(n)): " << linearTime << " ms (100 iterations)" << endl;
        
        // Sorting - O(n log n)
        vector<LogEntry> sortedLogs = *logs;
        double sortTime = measureTime([&sortedLogs]() {
            sort(sortedLogs.begin(), sortedLogs.end(), 
                 [](const LogEntry& a, const LogEntry& b) {
                     return a.timestamp < b.timestamp;
                 });
        });
        cout << "Sorting (O(n log n)): " << sortTime << " ms" << endl;
        
        // Binary Search - O(log n) (on sorted array)
        double binaryTime = measureTime([&sortedLogs]() {
            for (int i = 0; i < 100; i++) {
                auto it = lower_bound(sortedLogs.begin(), sortedLogs.end(), 
                                    LogEntry("2024-01-01", "", "", ""),
                                    [](const LogEntry& a, const LogEntry& b) {
                                        return a.timestamp < b.timestamp;
                                    });
            }
        });
        cout << "Binary Search (O(log n)): " << binaryTime << " ms (100 iterations)" << endl;
        
        // Hash Map Lookup - O(1)
        unordered_map<string, vector<LogEntry>> ipMap;
        for (const auto& log : *logs) {
            ipMap[log.ipAddress].push_back(log);
        }
        
        double hashTime = measureTime([&ipMap]() {
            for (int i = 0; i < 1000; i++) {
                auto it = ipMap.find("192.168.1.1");
            }
        });
        cout << "Hash Map Lookup (O(1)): " << hashTime << " ms (1000 iterations)" << endl;
        
        // Performance comparison
        cout << "\n=== Performance Comparison ===" << endl;
        cout << "Hash Map is " << (linearTime / hashTime) << "x faster than Linear Search" << endl;
        cout << "Binary Search is " << (linearTime / binaryTime) << "x faster than Linear Search" << endl;
    }
    
    // Benchmark different sorting algorithms
    void benchmarkSorting() {
        if (logs->empty()) {
            cout << "No logs available for benchmarking." << endl;
            return;
        }
        
        cout << "\n=== Sorting Algorithm Benchmark ===" << endl;
        cout << "Dataset size: " << logs->size() << " logs" << endl;
        
        // Quick Sort
        vector<LogEntry> quickSortData = *logs;
        double quickSortTime = measureTime([&quickSortData]() {
            sort(quickSortData.begin(), quickSortData.end(),
                 [](const LogEntry& a, const LogEntry& b) {
                     return a.severity > b.severity;
                 });
        });
        cout << "Quick Sort: " << quickSortTime << " ms" << endl;
        
        // Merge Sort (using stable_sort)
        vector<LogEntry> mergeSortData = *logs;
        double mergeSortTime = measureTime([&mergeSortData]() {
            stable_sort(mergeSortData.begin(), mergeSortData.end(),
                       [](const LogEntry& a, const LogEntry& b) {
                           return a.severity > b.severity;
                       });
        });
        cout << "Merge Sort: " << mergeSortTime << " ms" << endl;
        
        // Heap Sort
        vector<LogEntry> heapSortData = *logs;
        double heapSortTime = measureTime([&heapSortData]() {
            make_heap(heapSortData.begin(), heapSortData.end(),
                     [](const LogEntry& a, const LogEntry& b) {
                         return a.severity < b.severity;
                     });
            sort_heap(heapSortData.begin(), heapSortData.end(),
                     [](const LogEntry& a, const LogEntry& b) {
                         return a.severity < b.severity;
                     });
        });
        cout << "Heap Sort: " << heapSortTime << " ms" << endl;
    }
    
    // Monitor performance of graph operations
    void monitorGraphPerformance(NetworkGraph* graph, BFSAnalyzer* bfs, DFSAnalyzer* dfs) {
        cout << "\n=== Graph Operations Performance ===" << endl;
        
        auto nodes = graph->getAllNodes();
        if (nodes.size() < 2) {
            cout << "Insufficient nodes for performance testing." << endl;
            return;
        }
        
        string firstNode = *nodes.begin();
        string secondNode = *next(nodes.begin());
        
        // BFS Performance
        double bfsTime = measureTime([&]() {
            for (int i = 0; i < 10; i++) {
                bfs->findShortestPath(firstNode, secondNode);
            }
        });
        cout << "BFS Shortest Path (O(V+E)): " << bfsTime << " ms (10 iterations)" << endl;
        
        // DFS Performance
        double dfsTime = measureTime([&]() {
            for (int i = 0; i < 10; i++) {
                vector<string> cyclePath;
                dfs->detectCommunicationCycle(firstNode, cyclePath);
            }
        });
        cout << "DFS Cycle Detection (O(V+E)): " << dfsTime << " ms (10 iterations)" << endl;
        
        graph->getGraphStats();
    }
};

// Advanced Algorithms Implementation
class AdvancedAlgorithms {
private:
    vector<LogEntry>* logs;
    unordered_map<string, vector<LogEntry>> ipHashTable;
    
    // Quick sort implementation
    void quickSort(vector<LogEntry>& arr, int low, int high, 
                   function<bool(const LogEntry&, const LogEntry&)> comp) {
        if (low < high) {
            int pi = partition(arr, low, high, comp);
            quickSort(arr, low, pi - 1, comp);
            quickSort(arr, pi + 1, high, comp);
        }
    }
    
    int partition(vector<LogEntry>& arr, int low, int high,
                  function<bool(const LogEntry&, const LogEntry&)> comp) {
        LogEntry pivot = arr[high];
        int i = low - 1;
        
        for (int j = low; j < high; j++) {
            if (comp(arr[j], pivot)) {
                i++;
                swap(arr[i], arr[j]);
            }
        }
        swap(arr[i + 1], arr[high]);
        return i + 1;
    }
    
    // Merge sort implementation
    void mergeSort(vector<LogEntry>& arr, int left, int right,
                   function<bool(const LogEntry&, const LogEntry&)> comp) {
        if (left < right) {
            int mid = left + (right - left) / 2;
            mergeSort(arr, left, mid, comp);
            mergeSort(arr, mid + 1, right, comp);
            merge(arr, left, mid, right, comp);
        }
    }
    
    void merge(vector<LogEntry>& arr, int left, int mid, int right,
               function<bool(const LogEntry&, const LogEntry&)> comp) {
        vector<LogEntry> leftArr(arr.begin() + left, arr.begin() + mid + 1);
        vector<LogEntry> rightArr(arr.begin() + mid + 1, arr.begin() + right + 1);
        
        int i = 0, j = 0, k = left;
        
        while (i < leftArr.size() && j < rightArr.size()) {
            if (comp(leftArr[i], rightArr[j])) {
                arr[k++] = leftArr[i++];
            } else {
                arr[k++] = rightArr[j++];
            }
        }
        
        while (i < leftArr.size()) {
            arr[k++] = leftArr[i++];
        }
        
        while (j < rightArr.size()) {
            arr[k++] = rightArr[j++];
        }
    }
    
public:
    AdvancedAlgorithms(vector<LogEntry>* logArray) : logs(logArray) {
        buildHashTable();
    }
    
    // Build hash table for fast IP lookup
    void buildHashTable() {
        ipHashTable.clear();
        for (const auto& log : *logs) {
            ipHashTable[log.ipAddress].push_back(log);
        }
    }
    
    // Binary search by timestamp
    int binarySearchByTimestamp(const string& timestamp) {
        // First ensure logs are sorted by timestamp
        vector<LogEntry> sortedLogs = *logs;
        sort(sortedLogs.begin(), sortedLogs.end(),
             [](const LogEntry& a, const LogEntry& b) {
                 return a.timestamp < b.timestamp;
             });
        
        int left = 0, right = sortedLogs.size() - 1;
        
        while (left <= right) {
            int mid = left + (right - left) / 2;
            
            if (sortedLogs[mid].timestamp == timestamp) {
                return mid;
            } else if (sortedLogs[mid].timestamp < timestamp) {
                left = mid + 1;
            } else {
                right = mid - 1;
            }
        }
        
        return -1; // Not found
    }
    
    // Quick sort by severity
    void quickSortBySeverity(vector<LogEntry>& logArray) {
        quickSort(logArray, 0, logArray.size() - 1,
                 [](const LogEntry& a, const LogEntry& b) {
                     return a.severity > b.severity;
                 });
    }
    
    // Merge sort by IP address
    void mergeSortByIP(vector<LogEntry>& logArray) {
        mergeSort(logArray, 0, logArray.size() - 1,
                 [](const LogEntry& a, const LogEntry& b) {
                     return a.ipAddress < b.ipAddress;
                 });
    }
    
    // Fast IP lookup using hash table
    vector<LogEntry> findLogsByIP(const string& ip) {
        auto it = ipHashTable.find(ip);
        if (it != ipHashTable.end()) {
            return it->second;
        }
        return {};
    }
    
    // Pattern matching for attack detection
    vector<LogEntry> findSimilarIPs(const string& pattern) {
        vector<LogEntry> results;
        for (const auto& pair : ipHashTable) {
            if (pair.first.find(pattern) != string::npos) {
                results.insert(results.end(), pair.second.begin(), pair.second.end());
            }
        }
        return results;
    }
    
    // Multi-criteria sorting
    void multiCriteriaSort(vector<LogEntry>& logArray, const string& primaryCriteria, const string& secondaryCriteria) {
        sort(logArray.begin(), logArray.end(), [&](const LogEntry& a, const LogEntry& b) {
            // Primary criteria comparison
            int primaryCompare = 0;
            if (primaryCriteria == "timestamp") {
                primaryCompare = a.timestamp.compare(b.timestamp);
            } else if (primaryCriteria == "severity") {
                primaryCompare = (a.severity > b.severity) ? -1 : (a.severity < b.severity) ? 1 : 0;
            } else if (primaryCriteria == "ip") {
                primaryCompare = a.ipAddress.compare(b.ipAddress);
            }
            
            if (primaryCompare != 0) {
                return primaryCompare < 0;
            }
            
            // Secondary criteria comparison
            if (secondaryCriteria == "timestamp") {
                return a.timestamp < b.timestamp;
            } else if (secondaryCriteria == "severity") {
                return a.severity > b.severity;
            } else if (secondaryCriteria == "ip") {
                return a.ipAddress < b.ipAddress;
            }
            
            return false;
        });
    }
    
    // Display search and sort options
    void displaySearchSortMenu() {
        cout << "\n=== Advanced Search & Sort Options ===" << endl;
        cout << "1. Binary Search by Timestamp" << endl;
        cout << "2. Hash Table IP Lookup" << endl;
        cout << "3. Pattern Matching for IPs" << endl;
        cout << "4. Quick Sort by Severity" << endl;
        cout << "5. Merge Sort by IP" << endl;
        cout << "6. Multi-Criteria Sort" << endl;
        cout << "0. Back to Main Menu" << endl;
    }
};

// Enhanced Log Analyzer with all new features
class EnhancedLogAnalyzer {
private:
    vector<LogEntry> logArray;
    queue<LogEntry> logQueue;
    stack<LogEntry> alertStack;
    NetworkGraph networkGraph;
    BFSAnalyzer* bfsAnalyzer;
    DFSAnalyzer* dfsAnalyzer;
    BigOAnalyzer* bigOAnalyzer;
    AdvancedAlgorithms* advancedAlgs;
    
    // Communication tracking for graph building
    map<pair<string, string>, int> communicationCount;
    
    // Enhanced initialization
    void initializeAnalyzers() {
        bfsAnalyzer = new BFSAnalyzer(&networkGraph);
        dfsAnalyzer = new DFSAnalyzer(&networkGraph);
        bigOAnalyzer = new BigOAnalyzer(&logArray);
        advancedAlgs = new AdvancedAlgorithms(&logArray);
    }
    
    // Build network graph from logs
    void buildNetworkGraph() {
        communicationCount.clear();
        
        // Count communications between IPs
        for (const auto& log : logArray) {
            // Extract destination IP from action if possible
            string destIP = extractDestinationIP(log.action);
            if (!destIP.empty() && destIP != log.ipAddress) {
                auto commPair = make_pair(log.ipAddress, destIP);
                communicationCount[commPair]++;
            }
        }
        
        // Add edges to graph based on communication
        for (const auto& comm : communicationCount) {
            networkGraph.addEdge(comm.first.first, comm.first.second, comm.second);
        }
        
        // Add standalone nodes
        for (const auto& log : logArray) {
            networkGraph.addNode(log.ipAddress);
        }
    }
    
    // Extract destination IP from action string (simplified)
    string extractDestinationIP(const string& action) {
        // Simple pattern matching for demonstration
        if (action.find("to:") != string::npos) {
            size_t pos = action.find("to:") + 3;
            size_t end = action.find(" ", pos);
            if (end == string::npos) end = action.length();
            return action.substr(pos, end - pos);
        }
        return "";
    }
    
    // Generate random severity for demonstration
    int generateSeverity(const string& status, const string& action) {
        if (status == "403" || status == "401") return 8; // High severity
        if (action.find("admin") != string::npos) return 7;
        if (action.find("login") != string::npos) return 5;
        if (status == "200") return 2; // Low severity
        return 4; // Medium severity
    }
    
    // === Tambahan: Simpan log ke CSV ===
    void saveLogsToCSV(const string& filename = "log.csv") {
        ofstream file(filename);
        if (!file.is_open()) {
            cout << "Failed to open file for writing logs." << endl;
            return;
        }
        // Header
        file << "timestamp,ipAddress,action,status,severity\n";
        for (const auto& log : logArray) {
            string safeAction = log.action;
            replace(safeAction.begin(), safeAction.end(), ',', ';');
            file << log.timestamp << "," << log.ipAddress << "," << safeAction << "," << log.status << "," << log.severity << "\n";
        }
        file.close();
    }
    // === Tambahan: Baca log dari CSV ===
    void loadLogsFromCSV(const string& filename = "log.csv") {
        ifstream file(filename);
        if (!file.is_open()) {
            cout << "No existing log file found. Starting fresh." << endl;
            return;
        }
        string line;
        getline(file, line); // Skip header
        while (getline(file, line)) {
            stringstream ss(line);
            string ts, ip, act, st, sevStr;
            getline(ss, ts, ',');
            getline(ss, ip, ',');
            getline(ss, act, ',');
            getline(ss, st, ',');
            getline(ss, sevStr, ',');
            int sev = sevStr.empty() ? 1 : stoi(sevStr);
            LogEntry entry(ts, ip, act, st, sev);
            logArray.push_back(entry);
            logQueue.push(entry);
            if (sev >= 7) alertStack.push(entry);
        }
        file.close();
        // Rebuild graph and hash table
        buildNetworkGraph();
        advancedAlgs = new AdvancedAlgorithms(&logArray);
    }
    
public:
    EnhancedLogAnalyzer() {
        initializeAnalyzers();
        loadLogsFromCSV(); // <-- Load log dari file saat inisialisasi
    }
    
    ~EnhancedLogAnalyzer() {
        delete bfsAnalyzer;
        delete dfsAnalyzer;
        delete bigOAnalyzer;
        delete advancedAlgs;
    }
    
    // Enhanced add log with network graph building
    void addLog(const string& timestamp, const string& ip, const string& action, const string& status) {
        int severity = generateSeverity(status, action);
        LogEntry entry(timestamp, ip, action, status, severity);
        
        logArray.push_back(entry);
        logQueue.push(entry);
        
        // Update network graph
        buildNetworkGraph();
        
        // Rebuild hash table for fast lookups
        advancedAlgs = new AdvancedAlgorithms(&logArray);
        
        // Alert for high severity
        if (severity >= 7) {
            alertStack.push(entry);
        }
        saveLogsToCSV(); // <-- Simpan log ke file setiap kali tambah log
    }
    
    // Network topology analysis
    void analyzeNetworkTopology() {
        cout << "\n=== Network Topology Analysis ===" << endl;
        
        if (networkGraph.getAllNodes().empty()) {
            cout << "No network data available. Please add some logs first." << endl;
            return;
        }
        
        networkGraph.displayGraph();
        networkGraph.getGraphStats();
        
        // Find most connected nodes (potential central targets)
        auto nodes = networkGraph.getAllNodes();
        string mostConnected;
        int maxConnections = 0;
        
        for (const string& node : nodes) {
            int connections = networkGraph.getNeighbors(node).size();
            if (connections > maxConnections) {
                maxConnections = connections;
                mostConnected = node;
            }
        }
        
        if (!mostConnected.empty()) {
            cout << "\nMost Connected Node (Potential Target): " << mostConnected 
                 << " with " << maxConnections << " connections" << endl;
        }
    }
    
    // Attack pattern detection using BFS
    void detectAttackPatterns() {
        cout << "\n=== Attack Pattern Detection (BFS) ===" << endl;
        
        auto nodes = networkGraph.getAllNodes();
        if (nodes.size() < 2) {
            cout << "Insufficient network data for pattern detection." << endl;
            return;
        }
        
        // Analyze suspicious communication patterns
        for (const string& suspiciousIP : {"345.67.89.10", "789.12.34.56"}) {
            if (networkGraph.hasNode(suspiciousIP)) {
                cout << "\nAnalyzing suspicious IP: " << suspiciousIP << endl;
                
                // Find nodes within 2 hops (potential lateral movement)
                vector<string> nearbyNodes = bfsAnalyzer->getNodesInRadius(suspiciousIP, 2);
                cout << "Nodes within 2 hops: ";
                for (const string& node : nearbyNodes) {
                    cout << node << " ";
                }
                cout << endl;
                
                // Map network layers from suspicious IP
                auto layers = bfsAnalyzer->mapNetworkLayers(suspiciousIP);
                cout << "Network layers from " << suspiciousIP << ":" << endl;
                for (const auto& layer : layers) {
                    cout << "Layer " << layer.first << ": ";
                    for (const string& node : layer.second) {
                        cout << node << " ";
                    }
                    cout << endl;
                }
            }
        }
    }
    
    // Trace attack paths using DFS
    void traceAttackPaths() {
        cout << "\n=== Attack Path Tracing (DFS) ===" << endl;
        
        auto nodes = networkGraph.getAllNodes();
        if (nodes.empty()) {
            cout << "No network data available." << endl;
            return;
        }
        
        // Check for communication cycles (potential backdoors)
        for (const string& node : nodes) {
            vector<string> cyclePath;
            if (dfsAnalyzer->detectCommunicationCycle(node, cyclePath)) {
                cout << "Potential backdoor detected starting from " << node << endl;
                cout << "Cycle path: ";
                for (const string& pathNode : cyclePath) {
                    cout << pathNode << " -> ";
                }
                cout << endl;
                break;
            }
        }
        
        // Vulnerability assessment for high-value targets
        string targetIP = "192.168.1.1"; // Assume this is a critical server
        if (networkGraph.hasNode(targetIP)) {
            dfsAnalyzer->assessVulnerabilityDepth(targetIP);
        }
    }
    
    // Performance analysis
    void performanceAnalysis() {
        cout << "\n=== Performance Analysis ===" << endl;
        
        if (logArray.empty()) {
            cout << "No logs available for performance analysis." << endl;
            return;
        }
        
        bigOAnalyzer->analyzeComplexity();
        bigOAnalyzer->benchmarkSorting();
        bigOAnalyzer->monitorGraphPerformance(&networkGraph, bfsAnalyzer, dfsAnalyzer);
    }
    
    // Advanced search and sort interface
    void advancedSearchSort() {
        int choice;
        do {
            advancedAlgs->displaySearchSortMenu();
            cout << "Choice: ";
            cin >> choice;
            
            switch (choice) {
                case 1: {
                    string timestamp;
                    cin.ignore();
                    cout << "Enter timestamp to search: ";
                    getline(cin, timestamp);
                    
                    int index = advancedAlgs->binarySearchByTimestamp(timestamp);
                    if (index != -1) {
                        cout << "Found at index: " << index << endl;
                    } else {
                        cout << "Timestamp not found." << endl;
                    }
                    break;
                }
                case 2: {
                    string ip;
                    cin.ignore();
                    cout << "Enter IP address: ";
                    getline(cin, ip);
                    
                    auto logs = advancedAlgs->findLogsByIP(ip);
                    cout << "Found " << logs.size() << " logs for IP " << ip << endl;
                    for (const auto& log : logs) {
                        log.display();
                    }
                    break;
                }
                case 3: {
                    string pattern;
                    cin.ignore();
                    cout << "Enter IP pattern: ";
                    getline(cin, pattern);
                    
                    auto logs = advancedAlgs->findSimilarIPs(pattern);
                    cout << "Found " << logs.size() << " logs matching pattern " << pattern << endl;
                    break;
                }
                case 4: {
                    vector<LogEntry> sortedLogs = logArray;
                    advancedAlgs->quickSortBySeverity(sortedLogs);
                    cout << "Logs sorted by severity (Quick Sort):" << endl;
                    for (size_t i = 0; i < min((size_t)10, sortedLogs.size()); i++) {
                        sortedLogs[i].display();
                    }
                    break;
                }
                case 5: {
                    vector<LogEntry> sortedLogs = logArray;
                    advancedAlgs->mergeSortByIP(sortedLogs);
                    cout << "Logs sorted by IP (Merge Sort):" << endl;
                    for (size_t i = 0; i < min((size_t)10, sortedLogs.size()); i++) {
                        sortedLogs[i].display();
                    }
                    break;
                }
                case 6: {
                    string primary, secondary;
                    cin.ignore();
                    cout << "Primary criteria (timestamp/severity/ip): ";
                    getline(cin, primary);
                    cout << "Secondary criteria (timestamp/severity/ip): ";
                    getline(cin, secondary);
                    
                    vector<LogEntry> sortedLogs = logArray;
                    advancedAlgs->multiCriteriaSort(sortedLogs, primary, secondary);
                    cout << "Logs sorted by " << primary << " then " << secondary << ":" << endl;
                    for (size_t i = 0; i < min((size_t)10, sortedLogs.size()); i++) {
                        sortedLogs[i].display();
                    }
                    break;
                }
            }
        } while (choice != 0);
    }
    
    // Existing methods (simplified for brevity)
    void processLogs() {
        cout << "Processing " << logQueue.size() << " logs..." << endl;
        while (!logQueue.empty()) {
            logQueue.pop();
        }
        cout << "All logs processed." << endl;
    }
    
    void viewAllLogs() {
        if (logArray.empty()) {
            cout << "No logs available." << endl;
            return;
        }
        
        cout << "All Logs (" << logArray.size() << "):" << endl;
        for (size_t i = 0; i < logArray.size(); i++) {
            cout << i + 1 << ". ";
            logArray[i].display();
        }
    }
    
    void viewRecentAlerts(int count = 5) {
        if (alertStack.empty()) {
            cout << "No alerts available." << endl;
            return;
        }
        
        cout << "Recent Alerts (" << min(count, (int)alertStack.size()) << "):" << endl;
        
        stack<LogEntry> tempStack;
        int num = 0;
        
        while (!alertStack.empty() && num < count) {
            LogEntry entry = alertStack.top();
            alertStack.pop();
            
            cout << num + 1 << ". ";
            entry.display();
            
            tempStack.push(entry);
            num++;
        }
        
        while (!tempStack.empty()) {
            alertStack.push(tempStack.top());
            tempStack.pop();
        }
    }
    
    // Algorithm benchmark comparison
    void benchmarkAlgorithms() {
        cout << "\n=== Algorithm Benchmark Comparison ===" << endl;
        
        if (logArray.size() < 1000) {
            cout << "Generating additional test data for meaningful benchmarks..." << endl;
            // Generate test data
            for (int i = 0; i < 1000; i++) {
                string ip = "192.168." + to_string(rand() % 255) + "." + to_string(rand() % 255);
                string action = "HTTP GET /test" + to_string(i);
                string status = (rand() % 10 == 0) ? "403" : "200";
                addLog("2024-01-01 " + to_string(i % 24) + ":00:00", ip, action, status);
            }
        }
        
        bigOAnalyzer->benchmarkSorting();
        
        // Additional custom benchmarks
        cout << "\n=== Search Algorithm Comparison ===" << endl;
        
        // Linear vs Binary vs Hash search comparison
        vector<LogEntry> sortedLogs = logArray;
        sort(sortedLogs.begin(), sortedLogs.end(),
             [](const LogEntry& a, const LogEntry& b) {
                 return a.timestamp < b.timestamp;
             });
        
        string searchTarget = logArray[logArray.size() / 2].timestamp;
        
        auto start = high_resolution_clock::now();
        // Linear search
        for (int i = 0; i < 100; i++) {
            for (const auto& log : logArray) {
                if (log.timestamp == searchTarget) break;
            }
        }
        auto end = high_resolution_clock::now();
        double linearTime = duration_cast<microseconds>(end - start).count() / 1000.0;
        
        start = high_resolution_clock::now();
        // Binary search
        for (int i = 0; i < 100; i++) {
            advancedAlgs->binarySearchByTimestamp(searchTarget);
        }
        end = high_resolution_clock::now();
        double binaryTime = duration_cast<microseconds>(end - start).count() / 1000.0;
        
        cout << "Linear Search: " << linearTime << " ms" << endl;
        cout << "Binary Search: " << binaryTime << " ms" << endl;
        cout << "Binary Search is " << (linearTime / binaryTime) << "x faster" << endl;
    }
};

// Utility functions
string getCurrentTimestamp() {
    time_t now = time(0);
    tm* localTime = localtime(&now);
    char buf[80];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localTime);
    return string(buf);
}

void displayEnhancedMenu() {
    cout << "\n===== ENHANCED CYBER SECURITY LOG ANALYZER =====\n";
    cout << "Basic Operations:" << endl;
    cout << "1.  Add Log Manual" << endl;
    cout << "2.  Process Logs" << endl;
    cout << "3.  View All Logs" << endl;
    cout << "4.  View Recent Alerts" << endl;
    cout << "\nGraph & Network Analysis:" << endl;
    cout << "5.  Analyze Network Topology" << endl;
    cout << "6.  Detect Attack Patterns (BFS)" << endl;
    cout << "7.  Trace Attack Paths (DFS)" << endl;
    cout << "\nPerformance & Algorithms:" << endl;
    cout << "8.  Performance Analysis (Big O)" << endl;
    cout << "9.  Advanced Search & Sort" << endl;
    cout << "10. Benchmark Algorithms" << endl;
    cout << "\n0.  Exit" << endl;
    cout << "Choice: ";
}

int main() {
    EnhancedLogAnalyzer analyzer;
    int choice;
    
    // Add sample data with network connections
    // analyzer.addLog(getCurrentTimestamp(), "192.168.1.1", "HTTP GET /login", "200");
    // analyzer.addLog(getCurrentTimestamp(), "192.168.1.100", "HTTP POST to:192.168.1.1 /api", "200");
    // analyzer.addLog(getCurrentTimestamp(), "345.67.89.10", "HTTP POST to:192.168.1.1 /admin", "403");
    // analyzer.addLog(getCurrentTimestamp(), "345.67.89.10", "HTTP GET to:192.168.1.100 /data", "403");
    // analyzer.addLog(getCurrentTimestamp(), "192.168.1.50", "HTTPS GET to:192.168.1.1 /secure", "200");
    // analyzer.addLog(getCurrentTimestamp(), "789.12.34.56", "HTTP POST to:192.168.1.1 /login", "401");
    // analyzer.addLog(getCurrentTimestamp(), "192.168.1.1", "HTTP RESPONSE to:192.168.1.100", "200");
    // analyzer.addLog(getCurrentTimestamp(), "10.0.0.1", "HTTPS POST to:192.168.1.1 /api/data", "200");
    
    cout << "Enhanced Cyber Security Log Analyzer initialized with sample data." << endl;
    cout << "This implementation includes Graph, BFS, DFS, Big O Analysis, and Advanced Algorithms." << endl;
    
    do {
        displayEnhancedMenu();
        cin >> choice;
        
        switch (choice) {
            case 1: {
                string ip, action, status;
                cin.ignore();
                cout << "Enter IP: ";
                getline(cin, ip);
                cout << "Enter Action: ";
                getline(cin, action);
                cout << "Enter Status: ";
                getline(cin, status);
                
                analyzer.addLog(getCurrentTimestamp(), ip, action, status);
                cout << "Log added successfully." << endl;
                break;
            }
            case 2:
                analyzer.processLogs();
                break;
            case 3:
                analyzer.viewAllLogs();
                break;
            case 4:
                analyzer.viewRecentAlerts();
                break;
            case 5:
                analyzer.analyzeNetworkTopology();
                break;
            case 6:
                analyzer.detectAttackPatterns();
                break;
            case 7:
                analyzer.traceAttackPaths();
                break;
            case 8:
                analyzer.performanceAnalysis();
                break;
            case 9:
                analyzer.advancedSearchSort();
                break;
            case 10:
                analyzer.benchmarkAlgorithms();
                break;
            case 0:
                cout << "Thank you for using Enhanced Cyber Security Log Analyzer!" << endl;
                break;
            default:
                cout << "Invalid choice." << endl;
        }
    } while (choice != 0);
    
    return 0;
}