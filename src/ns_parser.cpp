#include <cstring>
#include <iostream>
#include <map>
#include <vector>

#include "MessageParser.h"
#include "RData.h"
#include "RDataFactory.h"
#include "dns_constants.h"
#include "dns_structures.h"
#include "formatters.h"
#include "input.h"

int main() {
  /* Enter your code here. Read input from STDIN. Print output to STDOUT */
  try {
    std::vector<uint8_t> raw_data = get_raw_data(std::cin);
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
