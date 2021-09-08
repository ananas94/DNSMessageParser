#include <cstring>
#include <iostream>
#include <map>
#include <sstream>
#include <vector>

#include "RData.h"
#include "RDataFactory.h"
#include "dns_constants.h"
#include "dns_structures.h"

// could be linux/windows C-functions, but platform is unspecified in task,
// so make own implementations
uint16_t ntoh(uint16_t net) {
// macro is not standard. constexpr(std::endian) is c++20 feature
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  uint16_t ret = (net & 0xff) << 8 | (net & 0xff00) >> 8;
  return ret;
#else
  return net
#endif
}

uint32_t ntoh(uint32_t net) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  uint32_t ret = (net & 0xff000000) >> 24 | (net & 0xff0000) >> 8 |
                 (net & 0xff00) << 8 | (net & 0xff) << 24;
  return ret;
#else
  return net;
#endif
}
MessageParser::MessageParser(std::vector<uint8_t> &&message)
    : m_offset(0), m_raw_data(message) {}

template <typename T> T MessageParser::Get() {
  T ret;
  if (m_offset + sizeof(ret) > m_raw_data.size())
    throw std::invalid_argument("out of bound");
  std::memcpy(&ret, m_raw_data.data() + m_offset, sizeof(ret));
  m_offset += sizeof(ret);
  ret = ntoh(ret);
  return ret;
}

header_t MessageParser::GetHeader() {
  header_t ret;
  if (m_raw_data.size() < sizeof(uint16_t) * 6) {
    std::string errMsg("could not parse dns header");
    throw std::invalid_argument(errMsg);
  }

  ret.ID = Get<uint16_t>();

  uint16_t flags = Get<uint16_t>();

  ret.RCODE = flags & 0xF;
  ret.Z = (flags >> 4) & 0x111;
  ret.RA = (flags >> 7) & 0x1;
  ret.RD = (flags >> 8) & 0x1;
  ret.TC = (flags >> 9) & 0x1;
  ret.AA = (flags >> 10) & 0x1;
  ret.Opcode = (flags >> 11) & 0xF;
  ret.QR = flags >> 15;

  ret.QDCOUNT = Get<uint16_t>();
  ret.ANCOUNT = Get<uint16_t>();
  ret.NSCOUNT = Get<uint16_t>();
  ret.ARCOUNT = Get<uint16_t>();

  return ret;
}

std::string MessageParser::GetDomainName(bool couldBeCompressed) {
  char domain[MAX_NAME_LENGTH + 1];
  size_t dOffset = 0;
  domain[dOffset] = 0;

  size_t lSize;
  bool compressed = false;

  size_t offset = m_offset;
  uint8_t *data = m_raw_data.data();

  while ((offset < m_raw_data.size()) && ((lSize = data[offset]) != 0)) {
    if ((lSize & 0xC0) == 0xC0) {
      if (!couldBeCompressed)
        throw std::invalid_argument(
            "it shouldn't be compressed"); // rfc-2782...
      if (!compressed)
        m_offset += 1;
      compressed = true;
      if (offset + 1 >= m_raw_data.size())
        throw std::invalid_argument("out of bound");
      offset = ((data[offset] & 0x3f) << 8) | data[offset + 1];
      if (offset >= m_raw_data.size())
        throw std::invalid_argument("out of bound");
    } else {
      offset++;
      if (offset + lSize > m_raw_data.size())
        throw std::invalid_argument("out of bound");
      if (dOffset + lSize + 2 > MAX_NAME_LENGTH)
        throw std::invalid_argument("too long domain name");

      std::memcpy(domain + dOffset, data + offset, lSize);
      offset += lSize;
      dOffset += lSize;

      domain[dOffset] = '.';
      dOffset++;
      domain[dOffset] = 0;

      if (!compressed)
        m_offset = offset;
    }
  }
  m_offset++;
  return domain;
}

question_t MessageParser::GetQuestion() {
  question_t ret;

  ret.QNAME = GetDomainName();
  ret.QTYPE = Get<uint16_t>();
  ret.QCLASS = Get<uint16_t>();

  return ret;
}

resource_record_t MessageParser::GetResourceRecord() {
  resource_record_t ret;
  ret.NAME = GetDomainName();

  ret.TYPE = Get<uint16_t>();
  ret.CLASS = Get<uint16_t>();
  ret.TTL = Get<uint32_t>();

  ret.RDATA = GetRData(ret.TYPE);

  return ret;
}

std::vector<uint8_t> MessageParser::GetRawData(size_t length) {
  if ((m_offset + length) > m_raw_data.size())
    throw std::invalid_argument("out of bound");
  std::vector<uint8_t> ret(m_raw_data.begin() + m_offset,
                           m_raw_data.begin() + m_offset + length);

  m_offset += length;
  return ret;
}

// https://www.cloudflare.com/learning/dns/dns-records/
// I guess, it's enough to implement commonly-used subset and print hex for
// other things... +AAAA, which is hidden in A.
std::unique_ptr<RData> MessageParser::GetRData(uint16_t type) {
  RData *ret;

  uint16_t RDLENGTH = Get<uint16_t>();

  std::string typeName;
  if (types.find(type) != types.end())
    typeName = types.at(type);
  else
    typeName = "unknown(" + std::to_string(type) + ")";

  ret = RDataFactory::BuildRData(typeName, *this, RDLENGTH);

  return std::unique_ptr<RData>(ret);
}

dns_message_t MessageParser::GetDnsMessage() {
  dns_message_t ret;
  ret.Header = GetHeader();
  if (ret.Header.QDCOUNT > 0) {
    for (int i = 0; i < ret.Header.QDCOUNT; i++)
      ret.Question.push_back(GetQuestion());
  }
  if (ret.Header.ANCOUNT > 0) {
    for (int i = 0; i < ret.Header.ANCOUNT; i++)
      ret.Answer.push_back(GetResourceRecord());
  }

  if (ret.Header.NSCOUNT > 0) {
    for (int i = 0; i < ret.Header.NSCOUNT; i++)
      ret.Authority.push_back(GetResourceRecord());
  }
  if (ret.Header.ARCOUNT > 0) {
    for (int i = 0; i < ret.Header.ARCOUNT; i++)
      ret.Additional.push_back(GetResourceRecord());
  }
  return ret;
}

std::ostream &operator<<(std::ostream &os, header_t h) {

  /*
;; ->>HEADER<<- opcode: QUERY; status: NOERROR; id: 28028
;; Flags: qr rd ra; QUERY: 1; ANSWER: 1; AUTHORITY: 0; ADDITIONAL: 0
*/
  std::string opcode;
  if (opcodes.find(h.Opcode) != opcodes.end())
    opcode = opcodes.at(h.Opcode);
  else
    opcode = "unknown(" + std::to_string(h.Opcode) + ")";

  std::string status;
  if (statuses.find(h.RCODE) != statuses.end())
    status = statuses.at(h.RCODE);
  else
    status = "unknown(" + std::to_string(h.RCODE) + ")";

  std::stringstream flagss;
  flagss << (h.QR ? " qr" : "") << (h.AA ? " aa" : "") << (h.TC ? " tc" : "")
         << (h.RD ? " rd" : "") << (h.RA ? " ra" : "");
  std::string flags = flagss.str();

  os << ";; ->>HEADER<<- opcode: " << opcode << "; status: " << status
     << "; id: " << h.ID << std::endl;
  os << ";; Flags:" << flags;
  os << "; QUERY: " << h.QDCOUNT << "; ANSWER: " << h.ANCOUNT
     << "; AUTHORITY: " << h.NSCOUNT << "; ADDITIONAL: " << h.ARCOUNT;
  return os;
};

std::ostream &operator<<(std::ostream &os, question_t q) {
  /*
      ;; QUESTION SECTION:
      ;; example.com.            IN    A
  */
  std::string cl;
  std::string type;

  if (classes.find(q.QCLASS) != classes.end())
    cl = classes.at(q.QCLASS);
  else
    cl = "unknown(" + std::to_string(q.QCLASS) + ")";

  if (types.find(q.QTYPE) != types.end())
    type = types.at(q.QTYPE);
  else
    type = "unknown(" + std::to_string(q.QTYPE) + ")";

  os << ";; " << q.QNAME << "\t\t\t" << cl << "\t" << type;
  return os;
}

std::ostream &operator<<(std::ostream &os, const std::unique_ptr<RData> &d) {
  os << (std::string)*d;
  return os;
}

std::ostream &operator<<(std::ostream &os, const resource_record_t &r) {
  /*
  ;; ANSWER SECTION:
  example.com.        76391    IN    A    93.184.216.34
  */

  std::string cl;
  std::string type;

  if (classes.find(r.CLASS) != classes.end())
    cl = classes.at(r.CLASS);
  else
    cl = "unknown(" + std::to_string(r.CLASS) + ")";

  if (types.find(r.TYPE) != types.end())
    type = types.at(r.TYPE);
  else
    type = "unknown(" + std::to_string(r.TYPE) + ")";

  os << r.NAME << "\t\t" << r.TTL << "\t" << cl << "\t" << type << "\t"
     << r.RDATA;
  return os;
}

std::ostream &operator<<(std::ostream &os, const dns_message_t &d) {
  os << d.Header << std::endl << std::endl;
  if (d.Question.size()) {
    os << ";; QUESTION SECTION:";
    for (const auto &it : d.Question)
      os << std::endl << it;
  }
  if (d.Answer.size()) {
    std::cout << std::endl;
    std::cout << std::endl << ";; ANSWER SECTION:";
    for (const auto &it : d.Answer)
      os << std::endl << it;
  }
  if (d.Authority.size()) {
    std::cout << std::endl;
    std::cout << std::endl << ";; AUTHORATIVE NAMESERVERS SECTION:";
    for (const auto &it : d.Authority)
      os << std::endl << it;
  }
  if (d.Additional.size()) {
    std::cout << std::endl;
    std::cout << std::endl << ";; ADDITIONAL RECORDS SECTION:";
    for (const auto &it : d.Additional)
      os << std::endl << it;
  }
  return os;
}

uint8_t parse_raw(const char *buf) {
  unsigned int uintVal;
  if (sscanf(buf, "\\x%2x", &uintVal) != 1) {
    std::string errMsg;
    errMsg += "\"";
    errMsg += buf;
    errMsg += "\" could not be parsed as hex";
    throw std::invalid_argument(errMsg);
  }
  return uintVal;
}

std::vector<uint8_t> parse_input_string(std::string str) {

  size_t strSize = str.size();
  if (strSize % 4 != 2 || str[0] != '"' || str[strSize - 1] != '"') {
    std::string errMsg;
    errMsg += "\"";
    errMsg += str;
    errMsg += "\" is not hex formatted string";
    throw std::invalid_argument(errMsg);
  }

  const char *strCStr = str.c_str();
  std::vector<uint8_t> ret(strSize / 4);
  for (size_t i = 0; i < strSize / 4; i++) {
    ret[i] = parse_raw(strCStr + 1 + 4 * i);
  }
  return ret;
}

int main() {
  /* Enter your code here. Read input from STDIN. Print output to STDOUT */
  try {
    std::vector<uint8_t> raw_data;
    while (std::cin.good()) {
      raw_data.reserve(UDP_SIZE_LIMIT);
      std::string input;

      std::cin >> input;

      if ((input.size() == 1 && input[0] == '\\') || input.size() == 0)
        continue; // copy-paste to terminal from hackerrank add empty lines to
                  // input, so ignore 0-sized strings

      auto raw_string_data = parse_input_string(input);

      raw_data.insert(raw_data.end(), raw_string_data.begin(),
                      raw_string_data.end());
    }

    MessageParser mp(std::move(raw_data));

    dns_message_t dm = mp.GetDnsMessage();
    std::cout << dm << std::endl;
  } catch (std::invalid_argument
               &e) { // exceptions could be not optimal soulution, if broken
                     // message is a rule, not an exception
    std::cout << "could not parse input message" << e.what();
    throw;
  }

  return 0;
}
