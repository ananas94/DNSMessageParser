#include "MessageParser.h"
#include "RDataFactory.h"
#include "dns_constants.h"
#include <cstring>

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
  if ( offset == m_raw_data.size() && lSize != 0 )
  {
        throw std::invalid_argument("looks like message cut");
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
