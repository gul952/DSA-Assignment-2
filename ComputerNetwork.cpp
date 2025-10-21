// network_monitor.cpp
// Single-file Network Monitor for CS250 Assignment 2
// Build: g++ -std=c++17 -O2 -pthread network_monitor.cpp -o network_monitor
// Run: sudo ./network_monitor --iface enp0s3 --duration 60 --filter-src 0.0.0.0 --filter-dst 0.0.0.0

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <ctime>
#include <functional>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace std;

// ------------------------- Configurable parameters -------------------------
static const size_t MAX_PACKET_SIZE = 65536;
static const int MAIN_Q_CAPACITY = 8192;
static const int REPLAY_Q_CAPACITY = 4096;
static const int BACKUP_Q_CAPACITY = 4096;
static const int OVERSIZED_THRESHOLD = 50; // threshold count for skipping oversized packets
// ---------------------------------------------------------------------------

// ------------------------- Utility functions --------------------------------
string ts_to_string(const timespec &ts) {
    char buf[64];
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    char msbuf[8];
    snprintf(msbuf, sizeof(msbuf), ".%03ld", ts.tv_nsec / 1000000);
    return string(buf) + string(msbuf);
}

uint64_t now_ms() {
    using namespace chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

string ipv4_to_string(const uint8_t *b) {
    char s[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, b, s, sizeof(s));
    return string(s);
}
string ipv6_to_string(const uint8_t *b) {
    char s[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, b, s, sizeof(s));
    return string(s);
}
// ---------------------------------------------------------------------------

// ------------------------- Custom Stack (for parsing) -----------------------
template<typename T>
class Stack {
private:
    T* arr;
    int topIndex;
    int capacity;
    void resize() {
        int newcap = capacity * 2;
        T* tmp = new T[newcap];
        for (int i = 0; i <= topIndex; ++i) tmp[i] = arr[i];
        delete[] arr;
        arr = tmp;
        capacity = newcap;
    }
public:
    Stack(int init = 32) {
        capacity = init;
        arr = new T[capacity];
        topIndex = -1;
    }
    ~Stack() { delete[] arr; }
    void push(const T &v) {
        if (topIndex + 1 >= capacity) resize();
        arr[++topIndex] = v;
    }
    T pop() {
        if (topIndex < 0) throw runtime_error("Stack underflow");
        return arr[topIndex--];
    }
    T top() const {
        if (topIndex < 0) throw runtime_error("Stack empty");
        return arr[topIndex];
    }
    bool empty() const { return topIndex < 0; }
};
// ---------------------------------------------------------------------------

// ------------------------- Custom Queue (circular) --------------------------
template<typename T>
class Queue {
private:
    T* arr;
    int capacity;
    int head, tail, count;
    mutex m;
public:
    Queue(int cap = 1024) {
        capacity = cap;
        arr = new T[capacity];
        head = 0; tail = -1; count = 0;
    }
    ~Queue() { delete[] arr; }
    bool enqueue(const T &v) {
        lock_guard<mutex> lk(m);
        if (count == capacity) return false;
        tail = (tail + 1) % capacity;
        arr[tail] = v;
        ++count;
        return true;
    }
    bool dequeue(T &out) {
        lock_guard<mutex> lk(m);
        if (count == 0) return false;
        out = arr[head];
        head = (head + 1) % capacity;
        --count;
        return true;
    }
    int size() {
        lock_guard<mutex> lk(m);
        return count;
    }
    bool empty() { return size() == 0; }
    // peek nth element (non-destructive), returns false if out of range
    bool peek_n(int n, T &out) {
        lock_guard<mutex> lk(m);
        if (n < 0 || n >= count) return false;
        int idx = (head + n) % capacity;
        out = arr[idx];
        return true;
    }
};
// ---------------------------------------------------------------------------

// ------------------------- Packet representation ---------------------------
struct Packet {
    uint64_t id;
    timespec ts;
    size_t size;
    uint8_t *raw; // dynamic buffer
    string src_ip, dst_ip;
    int replay_attempts;
    vector<string> layers; // human-readable layer info
    Packet() : id(0), size(0), raw(nullptr), replay_attempts(0) {}
    ~Packet() { if (raw) delete[] raw; }
};
// ---------------------------------------------------------------------------

// ------------------------- Globals & Queues --------------------------------
atomic<bool> running(true);
atomic<uint64_t> next_packet_id(1);

Queue<Packet*> mainQueue(MAIN_Q_CAPACITY);
Queue<Packet*> dissectedQueue(MAIN_Q_CAPACITY);
Queue<Packet*> replayQueue(REPLAY_Q_CAPACITY);
Queue<Packet*> backupQueue(BACKUP_Q_CAPACITY);

mutex cout_mtx;
atomic<int> oversized_count(0);
// ---------------------------------------------------------------------------

// ------------------------- Packet helpers ----------------------------------
Packet* make_packet_copy(const uint8_t* buf, ssize_t len) {
    Packet* p = new Packet();
    p->id = next_packet_id++;
    clock_gettime(CLOCK_REALTIME, &p->ts);
    p->size = (size_t)len;
    p->raw = new uint8_t[p->size];
    memcpy(p->raw, buf, p->size);
    p->replay_attempts = 0;
    return p;
}
// ---------------------------------------------------------------------------

// ------------------------- Dissector ---------------------------------------
enum LayerType { LAYER_ETHERNET, LAYER_IPV4, LAYER_IPV6, LAYER_TCP, LAYER_UDP, LAYER_UNKNOWN };

struct ParseFrame {
    LayerType type;
    size_t offset;
    size_t length;
    ParseFrame() : type(LAYER_UNKNOWN), offset(0), length(0) {}
    ParseFrame(LayerType t, size_t o, size_t l) : type(t), offset(o), length(l) {}
};

// parse using a stack: push initial ethernet, pop and parse next
void dissect_packet(Packet* p) {
    Stack<ParseFrame> stk(8);
    stk.push(ParseFrame(LAYER_ETHERNET, 0, p->size));
    while (!stk.empty()) {
        ParseFrame f = stk.pop();
        if (f.type == LAYER_ETHERNET) {
            if (f.offset + sizeof(ether_header) > p->size) {
                p->layers.push_back("Ethernet: truncated");
                continue;
            }
            ether_header *eth = (ether_header*)(p->raw + f.offset);
            char macbuf[64];
            snprintf(macbuf, sizeof(macbuf), "Ethernet: dst=%02x:%02x:%02x:%02x:%02x:%02x src=%02x:%02x:%02x:%02x:%02x:%02x type=0x%04x",
                     eth->ether_dhost[0],eth->ether_dhost[1],eth->ether_dhost[2],eth->ether_dhost[3],eth->ether_dhost[4],eth->ether_dhost[5],
                     eth->ether_shost[0],eth->ether_shost[1],eth->ether_shost[2],eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5],
                     ntohs(eth->ether_type));
            p->layers.push_back(string(macbuf));
            uint16_t etype = ntohs(eth->ether_type);
            size_t newoff = f.offset + sizeof(ether_header);
            if (etype == ETH_P_IP) {
                stk.push(ParseFrame(LAYER_IPV4, newoff, p->size - newoff));
            } else if (etype == ETH_P_IPV6) {
                stk.push(ParseFrame(LAYER_IPV6, newoff, p->size - newoff));
            } else {
                // not one of the required five protocols: mark unknown
                p->layers.push_back("EtherType not IPv4/IPv6 -> skipping further parse");
            }
        } else if (f.type == LAYER_IPV4) {
            if (f.offset + sizeof(iphdr) > p->size) {
                p->layers.push_back("IPv4: truncated");
                continue;
            }
            iphdr *ip = (iphdr*)(p->raw + f.offset);
            int ihl = ip->ihl * 4;
            if (f.offset + ihl > p->size) {
                p->layers.push_back("IPv4: header truncated");
                continue;
            }
            uint8_t proto = ip->protocol;
            string src = ipv4_to_string((uint8_t*)&ip->saddr);
            string dst = ipv4_to_string((uint8_t*)&ip->daddr);
            p->src_ip = src; p->dst_ip = dst;
            char buf[128];
            snprintf(buf, sizeof(buf), "IPv4: %s -> %s proto=%u ihl=%d totlen=%u", src.c_str(), dst.c_str(), proto, ihl, ntohs(ip->tot_len));
            p->layers.push_back(string(buf));
            size_t newoff = f.offset + ihl;
            if (proto == IPPROTO_TCP) stk.push(ParseFrame(LAYER_TCP, newoff, p->size - newoff));
            else if (proto == IPPROTO_UDP) stk.push(ParseFrame(LAYER_UDP, newoff, p->size - newoff));
        } else if (f.type == LAYER_IPV6) {
            if (f.offset + sizeof(ip6_hdr) > p->size) {
                p->layers.push_back("IPv6: truncated");
                continue;
            }
            ip6_hdr *ip6 = (ip6_hdr*)(p->raw + f.offset);
            uint8_t nh = ip6->ip6_nxt;
            string src = ipv6_to_string((uint8_t*)&ip6->ip6_src);
            string dst = ipv6_to_string((uint8_t*)&ip6->ip6_dst);
            p->src_ip = src; p->dst_ip = dst;
            char buf[128];
            snprintf(buf, sizeof(buf), "IPv6: %s -> %s next_header=%u", src.c_str(), dst.c_str(), nh);
            p->layers.push_back(string(buf));
            size_t newoff = f.offset + sizeof(ip6_hdr);
            // NOTE: We do not implement full IPv6 extension header parsing here.
            if (nh == IPPROTO_TCP) stk.push(ParseFrame(LAYER_TCP, newoff, p->size - newoff));
            else if (nh == IPPROTO_UDP) stk.push(ParseFrame(LAYER_UDP, newoff, p->size - newoff));
        } else if (f.type == LAYER_TCP) {
            if (f.offset + sizeof(tcphdr) > p->size) {
                p->layers.push_back("TCP: truncated");
                continue;
            }
            tcphdr *tcp = (tcphdr*)(p->raw + f.offset);
            uint16_t sport = ntohs(tcp->source), dport = ntohs(tcp->dest);
            int doff = tcp->doff * 4;
            char buf[128];
            snprintf(buf, sizeof(buf), "TCP: %u -> %u hdrlen=%d", sport, dport, doff);
            p->layers.push_back(string(buf));
        } else if (f.type == LAYER_UDP) {
            if (f.offset + sizeof(udphdr) > p->size) {
                p->layers.push_back("UDP: truncated");
                continue;
            }
            udphdr *udp = (udphdr*)(p->raw + f.offset);
            uint16_t sport = ntohs(udp->source), dport = ntohs(udp->dest);
            char buf[128];
            snprintf(buf, sizeof(buf), "UDP: %u -> %u len=%u", sport, dport, ntohs(udp->len));
            p->layers.push_back(string(buf));
        }
    }
}
// ---------------------------------------------------------------------------

// ------------------------- Capture thread ----------------------------------
void capture_loop(const string &iface) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        lock_guard<mutex> lk(cout_mtx);
        perror("socket(AF_PACKET) open");
        running = false;
        return;
    }

    // bind to interface
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
        lock_guard<mutex> lk(cout_mtx);
        perror("SIOCGIFINDEX");
        close(sock);
        running = false;
        return;
    }
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        lock_guard<mutex> lk(cout_mtx);
        perror("bind");
        close(sock);
        running = false;
        return;
    }

    uint8_t buf[MAX_PACKET_SIZE];
    while (running) {
        ssize_t len = recvfrom(sock, buf, sizeof(buf), 0, nullptr, nullptr);
        if (len <= 0) continue;
        Packet* p = make_packet_copy(buf, len);
        if (!mainQueue.enqueue(p)) {
            // queue full: drop oldest (dequeue) and enqueue new
            Packet* tmp=nullptr;
            if (mainQueue.dequeue(tmp)) {
                delete tmp;
            }
            mainQueue.enqueue(p);
        }
        {
            lock_guard<mutex> lk(cout_mtx);
            cout << "[CAP] id=" << p->id << " size=" << p->size << " ts=" << ts_to_string(p->ts) << "\n";
        }
    }
    close(sock);
}
// ---------------------------------------------------------------------------

// ------------------------- Dissector thread --------------------------------
void dissector_loop() {
    while (running) {
        Packet* p = nullptr;
        if (!mainQueue.dequeue(p)) {
            this_thread::sleep_for(chrono::milliseconds(10));
            continue;
        }
        if (!p) continue;
        dissect_packet(p);
        // track oversized
        if (p->size > 1500) oversized_count++;
        // push to dissectedQueue
        if (!dissectedQueue.enqueue(p)) {
            // if full, drop oldest
            Packet* tmp=nullptr;
            if (dissectedQueue.dequeue(tmp)) { delete tmp; }
            dissectedQueue.enqueue(p);
        }
        {
            lock_guard<mutex> lk(cout_mtx);
            cout << "[DSC] id=" << p->id << " layers=" << p->layers.size() << " src=" << p->src_ip << " dst=" << p->dst_ip << "\n";
        }
    }
}
// ---------------------------------------------------------------------------

// ------------------------- Filter & move to replay -------------------------
string filter_src_ip = "";
string filter_dst_ip = "";
int oversized_skip_threshold = OVERSIZED_THRESHOLD;

bool ip_matches(const string &filter, const string &val) {
    if (filter.empty()) return true;
    if (filter == "0.0.0.0" || filter == "::") return true;
    return filter == val;
}

void filter_loop() {
    while (running) {
        Packet* p = nullptr;
        if (!dissectedQueue.dequeue(p)) {
            this_thread::sleep_for(chrono::milliseconds(20));
            continue;
        }
        if (!p) continue;
        // oversized logic
        if (p->size > 1500) {
            if (oversized_count > oversized_skip_threshold) {
                lock_guard<mutex> lk(cout_mtx);
                cout << "[FLT] skipping oversized packet id=" << p->id << " size=" << p->size << "\n";
                delete p;
                continue;
            }
        }
        if (ip_matches(filter_src_ip, p->src_ip) && ip_matches(filter_dst_ip, p->dst_ip)) {
            // add to replay queue
            if (!replayQueue.enqueue(p)) {
                // replay queue full: drop to backup
                backupQueue.enqueue(p);
                lock_guard<mutex> lk(cout_mtx);
                cout << "[FLT] replay queue full -> moved id=" << p->id << " to backup\n";
            } else {
                lock_guard<mutex> lk(cout_mtx);
                cout << "[FLT] moved id=" << p->id << " to replay (delay_ms=" << (p->size/1000.0) << ")\n";
            }
        } else {
            // not matching: drop / free
            delete p;
        }
    }
}
// ---------------------------------------------------------------------------

// ------------------------- Replay thread -----------------------------------
string iface_global = "";
bool simulate_failure = false;

int create_send_sock_and_fill_sll(const string &iface, struct sockaddr_ll &sll_out) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ-1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) { close(sock); return -1; }
    memset(&sll_out, 0, sizeof(sll_out));
    sll_out.sll_family = AF_PACKET;
    sll_out.sll_ifindex = ifr.ifr_ifindex;
    sll_out.sll_halen = ETH_ALEN;
    // destination MAC left zero if re-sending raw frame (frame includes its own dest MAC)
    return sock;
}

void replay_loop() {
    struct sockaddr_ll sll;
    int send_sock = create_send_sock_and_fill_sll(iface_global, sll);
    if (send_sock < 0) {
        lock_guard<mutex> lk(cout_mtx);
        perror("replay: create send socket");
        running = false;
        return;
    }

    while (running) {
        Packet* p = nullptr;
        if (!replayQueue.dequeue(p)) {
            this_thread::sleep_for(chrono::milliseconds(20));
            continue;
        }
        if (!p) continue;
        bool success = false;
        for (int attempt = 0; attempt < 3; ++attempt) { // 0,1,2 -> max 2 retries after first failure (total attempts=3)
            if (simulate_failure) {
                // simulate a failure on first two attempts for demonstration
                if (attempt < 2) {
                    lock_guard<mutex> lk(cout_mtx);
                    cout << "[RPLY] simulated send failure for id=" << p->id << " attempt=" << attempt+1 << "\n";
                    p->replay_attempts++;
                    this_thread::sleep_for(chrono::milliseconds(50));
                    continue;
                }
            }
            ssize_t sent = sendto(send_sock, p->raw, p->size, 0, (struct sockaddr*)&sll, sizeof(sll));
            if (sent == (ssize_t)p->size) {
                success = true;
                p->replay_attempts = attempt+1;
                lock_guard<mutex> lk(cout_mtx);
                cout << "[RPLY] sent id=" << p->id << " size=" << p->size << " attempts=" << p->replay_attempts << "\n";
                break;
            } else {
                p->replay_attempts = attempt+1;
                lock_guard<mutex> lk(cout_mtx);
                cerr << "[RPLY] send failed id=" << p->id << " attempt=" << attempt+1 << " errno=" << errno << " " << strerror(errno) << "\n";
                this_thread::sleep_for(chrono::milliseconds(100));
            }
        }
        if (!success) {
            if (!backupQueue.enqueue(p)) {
                // backup full: free packet to avoid leak
                lock_guard<mutex> lk(cout_mtx);
                cout << "[RPLY] backup full: dropping id=" << p->id << "\n";
                delete p;
            } else {
                lock_guard<mutex> lk(cout_mtx);
                cout << "[RPLY] moved id=" << p->id << " to backup after " << p->replay_attempts << " attempts\n";
            }
        } else {
            // successful send - free packet
            delete p;
        }
    }
    close(send_sock);
}
// ---------------------------------------------------------------------------

// ------------------------- Display helpers ---------------------------------
void show_current_packets(int limit=50) {
    lock_guard<mutex> lk(cout_mtx);
    cout << "=== Current dissected queue (up to " << limit << ") ===\n";
    for (int i = 0; i < limit; ++i) {
        Packet* p = nullptr;
        if (!dissectedQueue.peek_n(i, p)) break;
        cout << "id=" << p->id << " ts=" << ts_to_string(p->ts) << " size=" << p->size << " src=" << p->src_ip << " dst=" << p->dst_ip << "\n";
    }
}

void show_packet_layers(uint64_t id) {
    // scan replay, dissected and main queue to find the id
    Packet* found = nullptr;
    // linear search in dissectedQueue (safer because mainQueue holds raw not dissected)
    int size = dissectedQueue.size();
    for (int i = 0; i < size; ++i) {
        Packet* p = nullptr;
        if (!dissectedQueue.peek_n(i, p)) continue;
        if (p && p->id == id) { found = p; break; }
    }
    lock_guard<mutex> lk(cout_mtx);
    if (!found) {
        cout << "Packet id=" << id << " not found in dissected queue\n";
        return;
    }
    cout << "=== Packet id=" << found->id << " layers ===\n";
    for (auto &s : found->layers) cout << s << "\n";
}

void show_filtered_and_replay() {
    lock_guard<mutex> lk(cout_mtx);
    cout << "=== Replay queue (size=" << replayQueue.size() << ") ===\n";
    int sz = replayQueue.size();
    for (int i = 0; i < sz && i < 50; ++i) {
        Packet* p = nullptr;
        if (!replayQueue.peek_n(i, p)) break;
        cout << "id=" << p->id << " size=" << p->size << " est_delay_ms=" << (p->size / 1000.0) << "\n";
    }
    cout << "=== Backup queue (size=" << backupQueue.size() << ") ===\n";
    sz = backupQueue.size();
    for (int i = 0; i < sz && i < 50; ++i) {
        Packet* p = nullptr;
        if (!backupQueue.peek_n(i, p)) break;
        cout << "backup id=" << p->id << " attempts=" << p->replay_attempts << "\n";
    }
}
// ---------------------------------------------------------------------------

// ------------------------- Simple argument parse ---------------------------
void usage_and_exit(const char *prog) {
    cerr << "Usage: sudo " << prog << " --iface IFACE [--duration N] [--filter-src IP] [--filter-dst IP] [--simulate-failure]\n";
    exit(1);
}

int main(int argc, char **argv) {
    if (getuid() != 0) {
        cerr << "This program requires root. Please run with sudo.\n";
        return 1;
    }

    string iface = "";
    int duration = 60;
    filter_src_ip = "";
    filter_dst_ip = "";
    simulate_failure = false;

    for (int i = 1; i < argc; ++i) {
        string a = argv[i];
        if (a == "--iface" && i + 1 < argc) iface = argv[++i];
        else if (a == "--duration" && i + 1 < argc) duration = stoi(argv[++i]);
        else if (a == "--filter-src" && i + 1 < argc) filter_src_ip = argv[++i];
        else if (a == "--filter-dst" && i + 1 < argc) filter_dst_ip = argv[++i];
        else if (a == "--simulate-failure") simulate_failure = true;
        else usage_and_exit(argv[0]);
    }

    if (iface.empty()) {
        cerr << "Please supply --iface INTERFACE (e.g., enp0s3)\n";
        return 1;
    }
    iface_global = iface;

    cout << "Starting Network Monitor on iface=" << iface << " duration=" << duration << "s\n";
    cout << "Filters: src=" << (filter_src_ip.empty() ? "*" : filter_src_ip) << " dst=" << (filter_dst_ip.empty() ? "*" : filter_dst_ip) << "\n";
    if (simulate_failure) cout << "Simulate failure: ON\n";

    // start threads
    thread cap_thread(capture_loop, iface);
    thread dsc_thread(dissector_loop);
    thread flt_thread(filter_loop);
    thread rply_thread(replay_loop);

    // let it run for duration seconds for the demo
    for (int i = 0; i < duration; ++i) {
        this_thread::sleep_for(chrono::seconds(1));
        if (!running) break;
    }

    // After demo period, show some displays and attempt auto filter/replay demonstration
    cout << "\n=== Demo period ended. Displaying sample outputs ===\n";
    show_current_packets(20);

    // If user passed 0.0.0.0 for both filters, auto-select first dissected packet pair
    if (filter_src_ip.empty() || filter_dst_ip.empty()) {
        Packet* psel=nullptr;
        if (dissectedQueue.peek_n(0, psel) && psel) {
            if (filter_src_ip.empty()) filter_src_ip = psel->src_ip;
            if (filter_dst_ip.empty()) filter_dst_ip = psel->dst_ip;
            cout << "Auto-selected filter src=" << filter_src_ip << " dst=" << filter_dst_ip << "\n";
        } else {
            cout << "No dissected packets to auto-select filters.\n";
        }
    }

    // Set running true for a bit longer to process filter/replay demonstration
    cout << "Running additional 10 seconds to filter/replay using selected IPs...\n";
    // Let filter thread pick up items
    for (int i = 0; i < 10; ++i) {
        this_thread::sleep_for(chrono::seconds(1));
    }

    show_filtered_and_replay();
    // Show a packet's layers if any exist
    Packet* sample=nullptr;
    if (dissectedQueue.peek_n(0, sample) && sample) {
        cout << "Showing layers for first dissected packet id=" << sample->id << "\n";
        show_packet_layers(sample->id);
    }

    cout << "Demo complete. Shutting down threads...\n";
    // stop threads
    running = false;
    // join threads
    cap_thread.join();
    dsc_thread.join();
    flt_thread.join();
    rply_thread.join();

    // clean up remaining queued packets
    Packet* tmp=nullptr;
    while (mainQueue.dequeue(tmp)) { delete tmp; }
    while (dissectedQueue.dequeue(tmp)) { delete tmp; }
    while (replayQueue.dequeue(tmp)) { delete tmp; }
    while (backupQueue.dequeue(tmp)) { delete tmp; }

    cout << "Finished. Check backup queue saved packets count (for report demonstration): " << backupQueue.size() << "\n";
    return 0;
}


