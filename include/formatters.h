#include "dns_structures.h"
#include <iostream>
#include <sstream>
std::ostream &operator<<(std::ostream &os, header_t h);
std::ostream &operator<<(std::ostream &os, question_t q);
std::ostream &operator<<(std::ostream &os, const std::unique_ptr<RData> &d);
std::ostream &operator<<(std::ostream &os, const resource_record_t &r);
std::ostream &operator<<(std::ostream &os, const dns_message_t &d);
