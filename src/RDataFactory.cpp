#include "RDataFactory.h"
#include "GenericRData.h"
#include "RData.h"

bool RDataFactory::Register(std::string name, RDataBuilder builder) {
  RDataFactory::GetBuilders()[name] = builder;
  return true;
}
RData *RDataFactory::BuildRData(std::string name, MessageParser &mp,
                                size_t RDLENGTH) {
  if (RDataFactory::GetBuilders().find(name.c_str()) !=
      RDataFactory::GetBuilders().end())
    return RDataFactory::GetBuilders()[name.c_str()](mp, RDLENGTH);
  return new GenericRData(mp, RDLENGTH);
}

// on hot path std::string should be replaced with type as index of
// std::array<RDataBuilder,MAX_TYPE> not a problem for one time parser
std::unordered_map<std::string, RDataBuilder> &RDataFactory::GetBuilders() {
  static std::unordered_map<std::string, RDataBuilder> builders;
  return builders;
}
