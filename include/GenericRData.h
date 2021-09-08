#ifndef GENERIC_RDATA
#define GENERIC_RDATA

#include "MessageParser.h"
class GenericRData : public RData {
protected:
  std::vector<uint8_t> m_data;

public:
  GenericRData(MessageParser &mp, size_t RDLENGTH);
  virtual operator std::string();
};

#endif
