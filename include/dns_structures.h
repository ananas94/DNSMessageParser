#ifndef DNS_STRUCTURES
#define DNS_STRUCTURES

#include "RData.h"
#include <cstdint>
#include <memory>
#include <string>
#include <vector>
struct header_t {
  uint16_t ID;
  // not a real thing. could be usefull if we stick to big-endianness, platform,
  // compiller and sure about paddings
  uint16_t QR : 1, Opcode : 4, AA : 1, TC : 1, RD : 1, RA : 1, Z : 1, RCODE : 4;
  uint16_t QDCOUNT;
  uint16_t ANCOUNT;
  uint16_t NSCOUNT;
  uint16_t ARCOUNT;
};

struct question_t {
  std::string QNAME;
  uint16_t QTYPE;
  uint16_t QCLASS;
};

struct resource_record_t {
  std::string NAME;
  uint16_t TYPE;
  uint16_t CLASS;
  uint32_t TTL;
  std::unique_ptr<RData> RDATA;
};

struct dns_message_t {
  header_t Header;
  std::vector<question_t> Question;
  std::vector<resource_record_t> Answer;
  std::vector<resource_record_t> Authority;
  std::vector<resource_record_t> Additional;
};

#endif
