#include "GenericRData.h"
#include "RDataFactory.h"
#include <iomanip>
#include <sstream>

GenericRData::GenericRData(MessageParser &mp, size_t RDLENGTH) {
  m_data = mp.GetRawData(RDLENGTH);
}
GenericRData::operator std::string() {
  std::stringstream ss;
  ss << "unknown rdata(" << m_data.size() << ") hex: [";
  ss.setf(std::ios_base::hex, std::ios_base::basefield);
  ss.setf(std::ios_base::showbase);
  for (const uint8_t &it : m_data)
    ss << (int)(it) << " ";

  ss.unsetf(std::ios_base::hex);
  ss << "]";

  return ss.str();
}
class ARData : public RData, CRTPAutoRegistrator<ARData> {
  std::vector<uint8_t> m_data;
  ARData(MessageParser &mp, size_t RDLENGTH) {
    if (RDLENGTH != 4)
      throw std::invalid_argument("wrong rdata size for A record");
    m_data = mp.GetRawData(RDLENGTH);
  }

public:
  static const std::string GetDataType() { return "A"; };
  static RData *Builder(MessageParser &mp, size_t RDLENGTH) {
    return new ARData(mp, RDLENGTH);
  }

  virtual operator std::string() override {
    std::stringstream ss;
    for (size_t i = 0; i < m_data.size(); i++)
      ss << (int)(m_data)[i] << ((i != m_data.size() - 1) ? "." : "");
    return ss.str();
  }
};

class AAAARData : public RData, CRTPAutoRegistrator<AAAARData> {
  std::vector<uint8_t> m_data;
  AAAARData(MessageParser &mp, size_t RDLENGTH) {
    if (RDLENGTH != 16)
      throw std::invalid_argument("wrong rdata size for AAAA record");
    m_data = mp.GetRawData(RDLENGTH);
  };

public:
  static const std::string GetDataType() { return "AAAA"; };
  static RData *Builder(MessageParser &mp, size_t RDLENGTH) {
    return new AAAARData(mp, RDLENGTH);
  }
  virtual operator std::string() override {
    std::stringstream ss;

    ss.setf(std::ios_base::hex, std::ios_base::basefield);
    // could be improved with replacing zeros with :: and remove leading
    // zeros...
    for (size_t i = 0; i < m_data.size(); i += 2)
      ss << std::setw(2) << std::setfill('0') << (int)(m_data)[i]
         << std::setw(2) << std::setfill('0') << (int)(m_data)[i + 1]
         << ((i != m_data.size() - 2) ? ":" : "");

    ss.unsetf(std::ios_base::hex);
    return ss.str();
  }
};

class DomainRData : public RData {
  std::string m_domain;

public:
  DomainRData(MessageParser &mp, size_t RDLENGTH) {
    size_t offsetBefore = mp.GetCurrentOffset();

    m_domain = mp.GetDomainName();
    size_t offsetAfter = mp.GetCurrentOffset();

    //  RAII-offset-checker wouldn't work - we couldn't throw from destructor
    //  :-(
    if (offsetAfter - offsetBefore != RDLENGTH)
      throw std::invalid_argument("RDLENGTH not equial to domain name");
  }
  virtual operator std::string() override { return m_domain; }
};

class CNAMERData : public DomainRData, CRTPAutoRegistrator<CNAMERData> {
  CNAMERData(MessageParser &mp, size_t RDLENGTH) : DomainRData(mp, RDLENGTH) {}

public:
  static const std::string GetDataType() { return "CNAME"; };
  static RData *Builder(MessageParser &mp, size_t RDLENGTH) {
    return new CNAMERData(mp, RDLENGTH);
  }
};
class NSRData : public DomainRData, CRTPAutoRegistrator<NSRData> {
  NSRData(MessageParser &mp, size_t RDLENGTH) : DomainRData(mp, RDLENGTH) {}

public:
  static const std::string GetDataType() { return "NS"; };
  static RData *Builder(MessageParser &mp, size_t RDLENGTH) {
    return new NSRData(mp, RDLENGTH);
  }
};
class PTRRData : public DomainRData, CRTPAutoRegistrator<PTRRData> {
  PTRRData(MessageParser &mp, size_t RDLENGTH) : DomainRData(mp, RDLENGTH) {}

public:
  static const std::string GetDataType() { return "PTR"; };
  static RData *Builder(MessageParser &mp, size_t RDLENGTH) {
    return new PTRRData(mp, RDLENGTH);
  }
};

class MXRData : public RData, CRTPAutoRegistrator<MXRData> {
  MXRData(MessageParser &mp, size_t RDLENGTH) {
    size_t offsetBefore = mp.GetCurrentOffset();

    m_preference = mp.Get<uint16_t>();
    m_exchange = mp.GetDomainName();

    size_t offsetAfter = mp.GetCurrentOffset();
    if (offsetAfter - offsetBefore != RDLENGTH)
      throw std::invalid_argument("RDATA format error ");
  }
  uint16_t m_preference;
  std::string m_exchange;

public:
  static const std::string GetDataType() { return "MX"; };
  static RData *Builder(MessageParser &mp, size_t RDLENGTH) {
    return new MXRData(mp, RDLENGTH);
  }

  virtual operator std::string() override {
    return std::to_string(m_preference) + " " + m_exchange;
  }
};
class TXTRData : public RData, CRTPAutoRegistrator<TXTRData> {
  std::string m_str;
  TXTRData(MessageParser &mp, size_t RDLENGTH) {
    std::vector<uint8_t> raw_data = mp.GetRawData(RDLENGTH);
    m_str = std::string(raw_data.begin(), raw_data.end());
  }

public:
  static const std::string GetDataType() { return "TXT"; };
  static RData *Builder(MessageParser &mp, size_t RDLENGTH) {
    return new TXTRData(mp, RDLENGTH);
  }
  virtual operator std::string() override { return m_str; }
};

class SOARData : public RData, CRTPAutoRegistrator<SOARData> {
  std::string m_mname;
  std::string m_rname;
  uint32_t m_serial;
  uint32_t m_refresh;
  uint32_t m_retry;
  uint32_t m_expire;
  uint32_t m_minimum;
  SOARData(MessageParser &mp, size_t RDLENGTH) {
    size_t offsetBefore = mp.GetCurrentOffset();
    m_mname = mp.GetDomainName();
    m_rname = mp.GetDomainName();
    m_serial = mp.Get<uint32_t>();
    m_refresh = mp.Get<uint32_t>();
    m_retry = mp.Get<uint32_t>();
    m_expire = mp.Get<uint32_t>();
    m_minimum = mp.Get<uint32_t>();

    size_t offsetAfter = mp.GetCurrentOffset();
    if (offsetAfter - offsetBefore != RDLENGTH)
      throw std::invalid_argument("RDATA format error ");
  }

public:
  static const std::string GetDataType() { return "SOA"; };
  static RData *Builder(MessageParser &mp, size_t RDLENGTH) {
    return new SOARData(mp, RDLENGTH);
  }

  virtual operator std::string() override {
    return m_mname + " " + m_rname + " " + std::to_string(m_serial) + " " +
           std::to_string(m_refresh) + " " + std::to_string(m_retry) + " " +
           std::to_string(m_expire) + " " + std::to_string(m_minimum);
  }
};

// BTW, why SRV RR fields order is broken everywhere?
// why TTL class and type are reordered?!
class SRVRData : public RData, CRTPAutoRegistrator<SRVRData> {
  uint16_t m_priority;
  uint16_t m_weight;
  uint16_t m_port;
  std::string m_target;
  SRVRData(MessageParser &mp, size_t RDLENGTH) {
    size_t offsetBefore = mp.GetCurrentOffset();
    m_priority = mp.Get<uint16_t>();
    m_weight = mp.Get<uint16_t>();
    m_port = mp.Get<uint16_t>();

    const bool couldBeCompressed = false;
    m_target = mp.GetDomainName(couldBeCompressed);

    size_t offsetAfter = mp.GetCurrentOffset();
    if (offsetAfter - offsetBefore != RDLENGTH)
      throw std::invalid_argument("RDATA format error ");
  }

public:
  static const std::string GetDataType() { return "SRV"; };
  static RData *Builder(MessageParser &mp, size_t RDLENGTH) {
    return new SRVRData(mp, RDLENGTH);
  }

  virtual operator std::string() override {
    return std::to_string(m_priority) + " " + std::to_string(m_weight) + " " +
           std::to_string(m_port) + " " + m_target;
  }
};
