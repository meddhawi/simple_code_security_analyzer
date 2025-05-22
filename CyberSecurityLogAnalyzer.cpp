// CyberSecurityLogAnalyzer.cpp
// Aplikasi sederhana untuk menganalisis log keamanan jaringan
// Mengimplementasikan struktur data: array, queue, stack, linked list dan tree

#include <iostream>
#include <string>
#include <vector>
#include <queue>
#include <stack>
#include <map>
#include <ctime>
#include <fstream>

using namespace std;

// Struktur untuk menyimpan log aktivitas
struct LogEntry {
    string timestamp;
    string ipAddress;
    string action;
    string status;
    
    // Constructor
    LogEntry(string ts = "", string ip = "", string act = "", string st = "")
        : timestamp(ts), ipAddress(ip), action(act), status(st) {}
        
    // Menampilkan log
    void display() const {
        cout << "Timestamp: " << timestamp << ", IP: " << ipAddress 
             << ", Action: " << action << ", Status: " << status << endl;
    }
};

// Implementasi Linked List untuk menyimpan daftar IP mencurigakan
class SuspiciousIPList {
private:
    struct Node {
        string ipAddress;
        string reason;
        int occurrences;
        Node* next;
        
        Node(string ip, string r, int occ = 1) : ipAddress(ip), reason(r), occurrences(occ), next(nullptr) {}
    };
    
    Node* head;
    
public:
    SuspiciousIPList() : head(nullptr) {}
    
    // Destructor untuk membersihkan linked list
    ~SuspiciousIPList() {
        Node* current = head;
        while (current != nullptr) {
            Node* temp = current;
            current = current->next;
            delete temp;
        }
    }
    
    // Menambahkan IP ke dalam daftar mencurigakan
    void addIP(const string& ip, const string& reason) {
        Node* current = head;
        
        // Cek apakah IP sudah ada di dalam list
        while (current != nullptr) {
            if (current->ipAddress == ip) {
                current->occurrences++;
                return;
            }
            current = current->next;
        }
        
        // Jika tidak ada, tambahkan baru di depan
        Node* newNode = new Node(ip, reason);
        newNode->next = head;
        head = newNode;
    }
    
    // Menampilkan semua IP mencurigakan
    void displayAll() const {
        if (head == nullptr) {
            cout << "Tidak ada IP mencurigakan dalam daftar." << endl;
            return;
        }
        
        cout << "Daftar IP Mencurigakan:" << endl;
        Node* current = head;
        while (current != nullptr) {
            cout << "IP: " << current->ipAddress << ", Alasan: " << current->reason 
                 << ", Jumlah Kemunculan: " << current->occurrences << endl;
            current = current->next;
        }
    }
    
    // Mencari IP di dalam daftar
    bool findIP(const string& ip) const {
        Node* current = head;
        while (current != nullptr) {
            if (current->ipAddress == ip) {
                return true;
            }
            current = current->next;
        }
        return false;
    }
    
    // Menghapus IP dari daftar
    bool removeIP(const string& ip) {
        if (head == nullptr) {
            return false;
        }
        
        if (head->ipAddress == ip) {
            Node* temp = head;
            head = head->next;
            delete temp;
            return true;
        }
        
        Node* current = head;
        while (current->next != nullptr && current->next->ipAddress != ip) {
            current = current->next;
        }
        
        if (current->next != nullptr) {
            Node* temp = current->next;
            current->next = current->next->next;
            delete temp;
            return true;
        }
        
        return false;
    }
};

// Implementasi Decision Tree untuk klasifikasi serangan
class AttackClassifier {
private:
    struct TreeNode {
        string attribute;
        map<string, TreeNode*> children;
        string classification;
        
        TreeNode(string attr = "") : attribute(attr) {}
        
        ~TreeNode() {
            for (auto& pair : children) {
                delete pair.second;
            }
        }
    };
    
    TreeNode* root;
    
    // Fungsi bantuan untuk membangun pohon keputusan
    void buildDecisionTree() {
        // Membuat pohon keputusan sederhana
        root = new TreeNode("Asal IP");
        
        // Menambahkan cabang "Whitelist"
        TreeNode* whitelistNode = new TreeNode();
        whitelistNode->classification = "Aman";
        root->children["Whitelist"] = whitelistNode;
        
        // Menambahkan cabang "Blacklist"
        TreeNode* blacklistNode = new TreeNode();
        blacklistNode->classification = "Bahaya";
        root->children["Blacklist"] = blacklistNode;
        
        // Menambahkan cabang "Tidak Dikenal"
        TreeNode* unknownNode = new TreeNode("Protokol");
        root->children["Tidak Dikenal"] = unknownNode;
        
        // Menambahkan sub-cabang untuk "Tidak Dikenal" -> "Protokol"
        TreeNode* httpNode = new TreeNode("Frekuensi");
        unknownNode->children["HTTP"] = httpNode;
        
        TreeNode* httpsNode = new TreeNode();
        httpsNode->classification = "Mungkin Aman";
        unknownNode->children["HTTPS"] = httpsNode;
        
        TreeNode* otherNode = new TreeNode();
        otherNode->classification = "Perlu Investigasi";
        unknownNode->children["Lainnya"] = otherNode;
        
        // Menambahkan sub-cabang untuk "Tidak Dikenal" -> "Protokol" -> "HTTP" -> "Frekuensi"
        TreeNode* highFreqNode = new TreeNode();
        highFreqNode->classification = "Mungkin Berbahaya";
        httpNode->children["Tinggi"] = highFreqNode;
        
        TreeNode* lowFreqNode = new TreeNode();
        lowFreqNode->classification = "Mungkin Aman";
        httpNode->children["Rendah"] = lowFreqNode;
    }
    
public:
    AttackClassifier() {
        root = nullptr;
        buildDecisionTree();
    }
    
    ~AttackClassifier() {
        delete root;
    }
    
    // Klasifikasi berdasarkan pohon keputusan
    string classify(const string& ipStatus, const string& protocol, const string& frequency) {
        TreeNode* current = root;
        
        // Decision path untuk Asal IP
        if (current->attribute == "Asal IP") {
            auto it = current->children.find(ipStatus);
            if (it != current->children.end()) {
                current = it->second;
                
                // Jika sudah ada klasifikasi, langsung kembalikan
                if (!current->classification.empty()) {
                    return current->classification;
                }
            } else {
                return "Tidak Dapat Diklasifikasi";
            }
        }
        
        // Decision path untuk Protokol
        if (current->attribute == "Protokol") {
            auto it = current->children.find(protocol);
            if (it != current->children.end()) {
                current = it->second;
                
                // Jika sudah ada klasifikasi, langsung kembalikan
                if (!current->classification.empty()) {
                    return current->classification;
                }
            } else {
                return "Tidak Dapat Diklasifikasi";
            }
        }
        
        // Decision path untuk Frekuensi
        if (current->attribute == "Frekuensi") {
            auto it = current->children.find(frequency);
            if (it != current->children.end()) {
                current = it->second;
                return current->classification;
            }
        }
        
        return "Tidak Dapat Diklasifikasi";
    }
    
    // Menampilkan pohon keputusan (untuk keperluan debugging)
    void displayTree(TreeNode* node = nullptr, int depth = 0) {
        if (node == nullptr) {
            node = root;
        }
        
        for (int i = 0; i < depth; i++) {
            cout << "  ";
        }
        
        cout << "Attribute: " << node->attribute;
        if (!node->classification.empty()) {
            cout << " -> Classification: " << node->classification;
        }
        cout << endl;
        
        for (const auto& pair : node->children) {
            for (int i = 0; i < depth; i++) {
                cout << "  ";
            }
            cout << "Value: " << pair.first << " ->" << endl;
            displayTree(pair.second, depth + 1);
        }
    }
};

// Class utama untuk aplikasi Log Analyzer
class LogAnalyzer {
private:
    vector<LogEntry> logArray;  // Array untuk menyimpan semua log
    queue<LogEntry> logQueue;   // Queue untuk log yang perlu diproses
    stack<LogEntry> alertStack; // Stack untuk log yang mencurigakan
    SuspiciousIPList suspiciousIPs; // Linked List untuk IP mencurigakan
    AttackClassifier classifier; // Decision tree untuk klasifikasi serangan
    vector<string> whitelistedIPs; // Whitelist IP
    vector<string> blacklistedCountries; // Blacklist negara
    
    // Contoh data untuk whitelist dan blacklist
    void initializeWhitelistBlacklist() {
        // Whitelist IPs
        whitelistedIPs.push_back("192.168.1.1");
        whitelistedIPs.push_back("10.0.0.1");
        whitelistedIPs.push_back("172.16.0.1");
        
        // Blacklist countries (direpresentasikan dengan prefiks IP)
        blacklistedCountries.push_back("345."); // Contoh prefix IP untuk negara tertentu
        blacklistedCountries.push_back("789."); // Contoh prefix IP untuk negara tertentu
    }
    
    // Memeriksa apakah IP ada di whitelist
    bool isWhitelisted(const string& ip) {
        for (const auto& whiteIP : whitelistedIPs) {
            if (ip == whiteIP) {
                return true;
            }
        }
        return false;
    }
    
    // Memeriksa apakah IP berasal dari negara yang di-blacklist
    bool isFromBlacklistedCountry(const string& ip) {
        for (const auto& prefix : blacklistedCountries) {
            if (ip.find(prefix) == 0) {
                return true;
            }
        }
        return false;
    }
    
    // Menentukan status IP (Whitelist, Blacklist, atau Tidak Dikenal)
    string determineIPStatus(const string& ip) {
        if (isWhitelisted(ip)) {
            return "Whitelist";
        } else if (isFromBlacklistedCountry(ip) || suspiciousIPs.findIP(ip)) {
            return "Blacklist";
        } else {
            return "Tidak Dikenal";
        }
    }
    
    // Menentukan frekuensi akses (sederhana: hitung berapa kali IP muncul di log)
    string determineFrequency(const string& ip) {
        int count = 0;
        for (const auto& log : logArray) {
            if (log.ipAddress == ip) {
                count++;
            }
        }
        return (count > 5) ? "Tinggi" : "Rendah";
    }
    
    // Mengekstrak protokol dari log (misalnya HTTP, HTTPS, dll)
    string extractProtocol(const LogEntry& log) {
        if (log.action.find("HTTP") != string::npos) {
            return "HTTP";
        } else if (log.action.find("HTTPS") != string::npos) {
            return "HTTPS";
        } else {
            return "Lainnya";
        }
    }
    
public:
    LogAnalyzer() {
        initializeWhitelistBlacklist();
    }
    
    // Menambahkan log ke dalam sistem
    void addLog(const string& timestamp, const string& ip, const string& action, const string& status) {
        LogEntry entry(timestamp, ip, action, status);
        
        // Tambahkan ke array
        logArray.push_back(entry);
        
        // Tambahkan ke queue untuk diproses
        logQueue.push(entry);
        
        // Jika IP mencurigakan, tambahkan ke stack alert
        string ipStatus = determineIPStatus(ip);
        if (ipStatus == "Blacklist") {
            alertStack.push(entry);
            
            // Tambahkan ke daftar IP mencurigakan jika belum ada
            if (!suspiciousIPs.findIP(ip)) {
                suspiciousIPs.addIP(ip, "IP dari negara blacklist atau mencurigakan");
            }
        }
    }
    
    // Memproses semua log dalam queue
    void processLogs() {
        cout << "Memproses " << logQueue.size() << " log dalam antrian..." << endl;
        
        while (!logQueue.empty()) {
            LogEntry entry = logQueue.front();
            logQueue.pop();
            
            // Menentukan status keamanan log
            string ipStatus = determineIPStatus(entry.ipAddress);
            string protocol = extractProtocol(entry);
            string frequency = determineFrequency(entry.ipAddress);
            
            // Mengklasifikasikan log menggunakan decision tree
            string classification = classifier.classify(ipStatus, protocol, frequency);
            
            cout << "IP: " << entry.ipAddress << ", Klasifikasi: " << classification << endl;
            
            // Jika klasifikasi berbahaya, tambahkan ke daftar IP mencurigakan
            if (classification == "Bahaya" || classification == "Mungkin Berbahaya") {
                if (!suspiciousIPs.findIP(entry.ipAddress)) {
                    suspiciousIPs.addIP(entry.ipAddress, "Klasifikasi: " + classification);
                    alertStack.push(entry);
                }
            }
        }
    }
    
    // Melihat log terbaru yang mencurigakan (menggunakan stack)
    void viewRecentAlerts(int count = 5) {
        if (alertStack.empty()) {
            cout << "Tidak ada alert yang tercatat." << endl;
            return;
        }
        
        cout << "Alert Terbaru (" << min(count, (int)alertStack.size()) << "):" << endl;
        
        // Buat stack temporary untuk menyimpan data sementara
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
        
        // Kembalikan data ke stack asli
        while (!tempStack.empty()) {
            alertStack.push(tempStack.top());
            tempStack.pop();
        }
    }
    
    // Melihat semua log (menggunakan array)
    void viewAllLogs() {
        if (logArray.empty()) {
            cout << "Tidak ada log yang tersedia." << endl;
            return;
        }
        
        cout << "Semua Log (" << logArray.size() << "):" << endl;
        for (size_t i = 0; i < logArray.size(); i++) {
            cout << i + 1 << ". ";
            logArray[i].display();
        }
    }
    
    // Melihat semua IP mencurigakan (menggunakan linked list)
    void viewSuspiciousIPs() {
        suspiciousIPs.displayAll();
    }
    
    // Melihat struktur decision tree
    void viewDecisionTree() {
        cout << "Decision Tree untuk Klasifikasi Serangan:" << endl;
        classifier.displayTree();
    }
    
    // Menyimpan log ke file
    bool saveLogsToFile(const string& filename) {
        ofstream file(filename, ios::app);  // Open in append mode
        if (!file.is_open()) {
            return false;
        }
        
        for (const auto& log : logArray) {
            file << log.timestamp << "," << log.ipAddress << "," 
                 << log.action << "," << log.status << endl;
        }
        
        file.close();
        return true;
    }
    
    // Membaca log dari file
    bool loadLogsFromFile(const string& filename) {
        ifstream file(filename);
        if (!file.is_open()) {
            return false;
        }
        
        logArray.clear();
        
        string line;
        while (getline(file, line)) {
            size_t pos = 0;
            vector<string> tokens;
            
            // Parsing CSV sederhana
            string delimiter = ",";
            while ((pos = line.find(delimiter)) != string::npos) {
                tokens.push_back(line.substr(0, pos));
                line.erase(0, pos + delimiter.length());
            }
            tokens.push_back(line);
            
            if (tokens.size() >= 4) {
                addLog(tokens[0], tokens[1], tokens[2], tokens[3]);
            }
        }
        
        file.close();
        return true;
    }
};

// Fungsi bantuan untuk mendapatkan timestamp saat ini
string getCurrentTimestamp() {
    time_t now = time(0);
    tm* localTime = localtime(&now);
    char buf[80];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localTime);
    return string(buf);
}

// Fungsi untuk menampilkan menu
void displayMenu() {
    cout << "\n===== CYBER SECURITY LOG ANALYZER =====\n";
    cout << "1. Tambah Log Manual\n";
    cout << "2. Load Log dari File\n";
    cout << "3. Proses Log dalam Queue\n";
    cout << "4. Lihat Alert Terbaru\n";
    cout << "5. Lihat Semua Log\n";
    cout << "6. Lihat IP Mencurigakan\n";
    cout << "7. Tampilkan Decision Tree\n";
    cout << "8. Simpan Log ke File\n";
    cout << "0. Keluar\n";
    cout << "Pilihan: ";
}

int main() {
    LogAnalyzer analyzer;
    string filename;
    int choice;
    
    // Menambahkan beberapa contoh log
    analyzer.addLog(getCurrentTimestamp(), "192.168.1.1", "HTTP GET /login", "200");
    analyzer.addLog(getCurrentTimestamp(), "10.0.0.1", "HTTPS POST /api/data", "200");
    analyzer.addLog(getCurrentTimestamp(), "345.67.89.10", "HTTP POST /admin", "403");
    analyzer.addLog(getCurrentTimestamp(), "345.67.89.10", "HTTP GET /admin", "403");
    analyzer.addLog(getCurrentTimestamp(), "345.67.89.10", "HTTP GET /admin", "403");
    analyzer.addLog(getCurrentTimestamp(), "345.67.89.10", "HTTP GET /admin", "403");
    analyzer.addLog(getCurrentTimestamp(), "123.45.67.89", "HTTP GET /index.html", "200");
    analyzer.addLog(getCurrentTimestamp(), "98.76.54.32", "HTTPS GET /login", "200");
    analyzer.addLog(getCurrentTimestamp(), "789.12.34.56", "HTTP POST /login", "401");
    
    do {
        displayMenu();
        cin >> choice;
        
        switch (choice) {
            case 1: {
                string ip, action, status;
                cin.ignore();
                cout << "Masukkan IP: ";
                getline(cin, ip);
                cout << "Masukkan Aksi (mis. HTTP GET /login): ";
                getline(cin, action);
                cout << "Masukkan Status (mis. 200, 404): ";
                getline(cin, status);
                
                analyzer.addLog(getCurrentTimestamp(), ip, action, status);
                cout << "Log berhasil ditambahkan.\n";
                break;
            }
            case 2:
                cin.ignore();
                cout << "Masukkan nama file: ";
                getline(cin, filename);
                if (analyzer.loadLogsFromFile(filename)) {
                    cout << "Log berhasil dimuat dari file.\n";
                } else {
                    cout << "Gagal memuat log dari file.\n";
                }
                break;
            case 3:
                analyzer.processLogs();
                break;
            case 4:
                analyzer.viewRecentAlerts();
                break;
            case 5:
                analyzer.viewAllLogs();
                break;
            case 6:
                analyzer.viewSuspiciousIPs();
                break;
            case 7:
                analyzer.viewDecisionTree();
                break;
            case 8:
                cin.ignore();
                cout << "Masukkan nama file: ";
                getline(cin, filename);
                if (analyzer.saveLogsToFile(filename)) {
                    cout << "Log berhasil disimpan ke file.\n";
                } else {
                    cout << "Gagal menyimpan log ke file.\n";
                }
                break;
            case 0:
                cout << "Terima kasih telah menggunakan aplikasi!\n";
                break;
            default:
                cout << "Pilihan tidak valid.\n";
        }
    } while (choice != 0);
    
    return 0;
}