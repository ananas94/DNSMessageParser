#include "formatters.h"
#include "dns_constants.h"
std::ostream &operator<<(std::ostream &os, header_t h) {

  /*
;; ->>HEADER<<- opcode: QUERY; status: NOERROR; id: 28028
;; Flags: qr rd ra; QUERY: 1; ANSWER: 1; AUTHORITY: 0; ADDITIONAL: 0
*/
  std::string opcode;
  if (opcodes.find(h.Opcode) != opcodes.end())
    opcode = opcodes.at(h.Opcode);
  else
    opcode = "unknown(" + std::to_string(h.Opcode) + ")";

  std::string status;
  if (statuses.find(h.RCODE) != statuses.end())
    status = statuses.at(h.RCODE);
  else
    status = "unknown(" + std::to_string(h.RCODE) + ")";

  std::stringstream flagss;
  flagss << (h.QR ? " qr" : "") << (h.AA ? " aa" : "") << (h.TC ? " tc" : "")
         << (h.RD ? " rd" : "") << (h.RA ? " ra" : "");
  std::string flags = flagss.str();

  os << ";; ->>HEADER<<- opcode: " << opcode << "; status: " << status
     << "; id: " << h.ID << std::endl;
  os << ";; Flags:" << flags;
  os << "; QUERY: " << h.QDCOUNT << "; ANSWER: " << h.ANCOUNT
     << "; AUTHORITY: " << h.NSCOUNT << "; ADDITIONAL: " << h.ARCOUNT;
  return os;
};

std::ostream &operator<<(std::ostream &os, question_t q) {
  /*
      ;; QUESTION SECTION:
      ;; example.com.            IN    A
  */
  std::string cl;
  std::string type;

  if (classes.find(q.QCLASS) != classes.end())
    cl = classes.at(q.QCLASS);
  else
    cl = "unknown(" + std::to_string(q.QCLASS) + ")";

  if (types.find(q.QTYPE) != types.end())
    type = types.at(q.QTYPE);
  else
    type = "unknown(" + std::to_string(q.QTYPE) + ")";

  os << ";; " << q.QNAME << "\t\t\t" << cl << "\t" << type;
  return os;
}

std::ostream &operator<<(std::ostream &os, const std::unique_ptr<RData> &d) {
  os << (std::string)*d;
  return os;
}

std::ostream &operator<<(std::ostream &os, const resource_record_t &r) {
  /*
  ;; ANSWER SECTION:
  example.com.        76391    IN    A    93.184.216.34
  */

  std::string cl;
  std::string type;

  if (classes.find(r.CLASS) != classes.end())
    cl = classes.at(r.CLASS);
  else
    cl = "unknown(" + std::to_string(r.CLASS) + ")";

  if (types.find(r.TYPE) != types.end())
    type = types.at(r.TYPE);
  else
    type = "unknown(" + std::to_string(r.TYPE) + ")";

  os << r.NAME << "\t\t" << r.TTL << "\t" << cl << "\t" << type << "\t"
     << r.RDATA;
  return os;
}

std::ostream &operator<<(std::ostream &os, const dns_message_t &d) {
  os << d.Header << std::endl << std::endl;
  if (d.Question.size()) {
    os << ";; QUESTION SECTION:";
    for (const auto &it : d.Question)
      os << std::endl << it;
  }
  if (d.Answer.size()) {
    std::cout << std::endl;
    std::cout << std::endl << ";; ANSWER SECTION:";
    for (const auto &it : d.Answer)
      os << std::endl << it;
  }
  if (d.Authority.size()) {
    std::cout << std::endl;
    std::cout << std::endl << ";; AUTHORATIVE NAMESERVERS SECTION:";
    for (const auto &it : d.Authority)
      os << std::endl << it;
  }
  if (d.Additional.size()) {
    std::cout << std::endl;
    std::cout << std::endl << ";; ADDITIONAL RECORDS SECTION:";
    for (const auto &it : d.Additional)
      os << std::endl << it;
  }
  return os;
}

