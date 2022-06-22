#include <iostream>
#include <map>
#include <string>

using namespace std;

class Firewall {
private:
  int max_packets = 20;
  int max_packet_size = 100;
  int packets_count;
  map<int, bool> blocked_ips;
  int packets_array[20];

public:
  Firewall() {
    this->packets_count = 0;
    this->blocked_ips = map<int, bool>();
  }

  int packet_array_size() { return this->max_packets; }

  void block_ip(int ip) { blocked_ips[ip] = true; }

  void unblock_ip(int ip) { blocked_ips[ip] = false; }

  bool is_blocked(int ip) {
    if (blocked_ips.find(ip) == blocked_ips.end()) {
      return false;
    }
    return blocked_ips[ip];
  }

  void accept_packet(int ip, int packet) {
    if (packet > max_packet_size) {
      cerr << "Packet size is too big" << endl;
    }
    if (packets_count < max_packets && !is_blocked(ip)) {
      packets_array[packets_count] = packet;
      packets_count++;
    } else {
      if (is_blocked(ip)) {
        cerr << "Firewall rejected the packet from IP" << endl;
      } else {
        cerr << "Firewall queue is full" << endl;
      }
    }
  }

  int get_packet(int index) { return packets_array[index]; }

  void print_accepted_packets() {
    for (int i = 0; i < packets_count; i++) {
      cout << "Packet " << i << ": " << packets_array[i] << endl;
    }
  }
};

class Socket {
private:
  Firewall *firewall;
  int protocol;
  int port;
  int size;
  int ip;

public:
  Socket(Firewall *firewall) { this->firewall = firewall; }

  void connect(int protocol, int port, int size, int ip) {
    this->protocol = protocol;
    this->port = port;
    this->size = size;
    this->ip = ip;
  }

  void send(int packet) {
    firewall->accept_packet(this->ip, packet);
  }

  int receive(int index) {
    if (firewall->is_blocked(ip)) {
      cerr << "Packet blocked" << endl;
      return -1;
    }

    return firewall->get_packet(index - 1);
  }

  void close() { firewall->unblock_ip(ip); }

  void print_accepted_packets() { firewall->print_accepted_packets(); }

  ~Socket() { delete firewall; }
};

int main(int argc, char const *argv[]) {
  Firewall *firewall = new Firewall();
  Socket *socket = new Socket(firewall);

  socket->connect(1, 2, 3, 4);
  socket->send(42);
  socket->receive(1);

  socket->print_accepted_packets();

  firewall->block_ip(4);
  socket->send(43);
  socket->print_accepted_packets();

  socket->close();
  return 0;
}
