#ifndef RDATA_FACTORY
#define RDATA_FACTORY
#include "MessageParser.h"
#include "dns_structures.h"
#include <unordered_map>

typedef RData *(*RDataBuilder)(MessageParser &, size_t);
class RDataFactory {
public:
  static bool Register(std::string name, RDataBuilder builder);
  static RData *BuildRData(std::string name, MessageParser &mp,
                           size_t RDLENGTH);
  static std::unordered_map<std::string, RDataBuilder> &GetBuilders();
};

template <typename T> class CRTPAutoRegistrator {
  virtual bool DontOptimizeMyStatic() {
    return CRTPAutoRegistrator<T>::registrator;
  }
  static bool registrator;
};
template <typename T>
bool CRTPAutoRegistrator<T>::registrator =
    RDataFactory::Register(T::GetDataType(), T::Builder);

#endif
