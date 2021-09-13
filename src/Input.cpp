
#include <vector>
#include <iostream>
#include "dns_constants.h"

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

std::vector<uint8_t> get_raw_data(std::istream &is)
{
    std::vector<uint8_t> raw_data;
    raw_data.reserve(UDP_SIZE_LIMIT);

    while (is.good()) {
      std::string input;

      is >> input;

      if ((input.size() == 1 && input[0] == '\\') || input.size() == 0)
        continue; // copy-paste to terminal from hackerrank add empty lines to
                  // input, so ignore 0-sized strings

      auto raw_string_data = parse_input_string(input);

      raw_data.insert(raw_data.end(), raw_string_data.begin(),
                      raw_string_data.end());
    }
    return raw_data;
}
