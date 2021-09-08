#ifndef RDATA_DEF
#define RDATA_DEF
#include <string>

class RData {
public:
  virtual operator std::string() = 0;
  virtual ~RData() = default;
};

#endif
