#ifndef MESSAGE_PASER
#define MESSAGE_PASER
#include "dns_structures.h"

#include <memory>
#include <vector>
#include <cstring>

uint16_t ntoh(uint16_t net); 
uint32_t ntoh(uint32_t net);

class MessageParser {
public:
  MessageParser(std::vector<uint8_t> &&message);

  dns_message_t GetDnsMessage();
  header_t GetHeader();
  question_t GetQuestion();
  resource_record_t GetResourceRecord();
  std::unique_ptr<RData> GetRData(uint16_t type);
  std::string GetDomainName(bool couldBeCompressed = true);
  std::vector<uint8_t> GetRawData(size_t length);
  template <typename T> T Get()
  {
  T ret;
  if (m_offset + sizeof(ret) > m_raw_data.size())
    throw std::invalid_argument("out of bound");
  std::memcpy(&ret, m_raw_data.data() + m_offset, sizeof(ret));
  m_offset += sizeof(ret);
  ret = ntoh(ret);
  return ret;
}
  size_t GetCurrentOffset() { return m_offset; };

private:
  size_t m_offset;
  std::vector<uint8_t> m_raw_data;
};


#endif
