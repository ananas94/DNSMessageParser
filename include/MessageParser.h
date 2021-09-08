#ifndef MESSAGE_PASER
#define MESSAGE_PASER
#include "dns_structures.h"

#include <memory>
#include <vector>

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
  template <typename T> T Get();
  size_t GetCurrentOffset() { return m_offset; };

private:
  size_t m_offset;
  std::vector<uint8_t> m_raw_data;
};

#endif
