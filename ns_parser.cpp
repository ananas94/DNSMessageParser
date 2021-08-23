#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

const size_t UDP_SIZE_LIMIT = 512;
const size_t MAX_NAME_LENGTH = 255;

//All maps could be replaced by std::array
const std::unordered_map<uint16_t, std::string> types = {
    { 1, "A" },
    { 2, "NS" },
    { 3, "MD" },
    { 4, "MF" },
    { 5, "CNAME" },
    { 6, "SOA" },
    { 7, "MB" },
    { 8, "MG" },
    { 9, "MR" },
    { 10, "NULL" },
    { 11, "WKS" },
    { 12, "PTR" },
    { 13, "HINFO" },
    { 14, "MINFO" },
    { 15, "MX" },
    { 16, "TXT" },

    { 28, "AAAA" },
    { 33, "SRV" },

    { 252, "AXFR" }, //QTYPES
    { 253, "MAILB" },
    { 254, "MAILA" },
    { 255, "*" }
};

const std::unordered_map<uint16_t, std::string> classes = {
    { 1, "IN" },
    { 2, "CS" },
    { 3, "CH" },
    { 4, "HS" },
    { 255, "*" }, //QCLASS
};

const std::unordered_map<uint16_t, std::string> opcodes = {
    { 0, "QUERY" },
    { 1, "IQUERY" },
    { 2, "STATUS" }
};

const std::unordered_map<uint16_t, std::string> statuses = {
    { 0, "NOERROR" },
    { 1, "FORMATERROR" },
    { 2, "SERVERFAILURE" },
    { 3, "NAMEERROR" },
    { 4, "NOTIMPLEMENTED" },
    { 5, "REFUSED" },

};

struct header_t {
    uint16_t ID;
    //not a real thing. could be usefull if we stick to big-endianness, platform, compiller and sure about paddings
    uint16_t QR : 1, Opcode : 4, AA : 1, TC : 1, RD : 1, RA : 1, Z : 1, RCODE : 4;
    uint16_t QDCOUNT;
    uint16_t ANCOUNT;
    uint16_t NSCOUNT;
    uint16_t ARCOUNT;
};

struct question_t {
    std::string QNAME;
    uint16_t QTYPE;
    uint16_t QCLASS;
};

class RData;
struct resource_record_t {
    std::string NAME;
    uint16_t TYPE;
    uint16_t CLASS;
    uint32_t TTL;
    std::unique_ptr<RData> RDATA;
};

struct dns_message_t {
    header_t Header;
    std::vector<question_t> Question;
    std::vector<resource_record_t> Answer;
    std::vector<resource_record_t> Authority;
    std::vector<resource_record_t> Additional;
};

// could be linux/windows C-functions, but platform is unspecified in task,
// so make own implementations

uint16_t
ntoh(uint16_t net)
{
// macro is not standard. constexpr(std::endian) is c++20 feature
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint16_t ret = (net & 0xff) << 8 | (net & 0xff00) >> 8;
    return ret;
#else
    return net
#endif
}
uint32_t
ntoh(uint32_t net)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint32_t ret = (net & 0xff000000) >> 24 | (net & 0xff0000) >> 8 | (net & 0xff00) << 8 | (net & 0xff) << 24;
    return ret;
#else
    return net;
#endif
}

class MessageParser {
public:
    MessageParser(std::vector<uint8_t>&& message);

    dns_message_t GetDnsMessage();
    header_t GetHeader();
    question_t GetQuestion();
    resource_record_t GetResourceRecord();
    std::unique_ptr<RData> GetRData(uint16_t type);
    std::string GetDomainName(bool couldBeCompressed = true);
    std::vector<uint8_t> GetRawData(size_t length);
    template <typename T>
    T Get();
    size_t GetCurrentOffset() { return m_offset; };

private:
    size_t m_offset;
    std::vector<uint8_t> m_raw_data;
};

class RData {
public:
    virtual operator std::string() = 0;
    virtual ~RData() = default;
};

class GenericRData : public RData {
protected:
    std::vector<uint8_t> m_data;

public:
    GenericRData(MessageParser& mp, size_t RDLENGTH)
    {
        m_data = mp.GetRawData(RDLENGTH);
    }
    virtual operator std::string()
    {
        std::stringstream ss;
        ss << "unknown rdata(" << m_data.size() << ") hex: [";
        ss.setf(std::ios_base::hex, std::ios_base::basefield);
        ss.setf(std::ios_base::showbase);
        for (const uint8_t& it : m_data)
            ss << (int)(it) << " ";

        ss.unsetf(std::ios_base::hex);
        ss << "]";

        return ss.str();
    }
};

typedef RData* (*RDataBuilder)(MessageParser&, size_t);
class RDataFactory {
public:
    static bool Register(std::string name, RDataBuilder builder)
    {
        RDataFactory::GetBuilders()[name] = builder;
        return true;
    }
    static RData* BuildRData(std::string name, MessageParser& mp, size_t RDLENGTH)
    {
        if (RDataFactory::GetBuilders().find(name.c_str()) != RDataFactory::GetBuilders().end())
            return RDataFactory::GetBuilders()[name.c_str()](mp, RDLENGTH);
        return new GenericRData(mp, RDLENGTH);
    }

    // on hot path std::string should be replaced with type as index of std::array<RDataBuilder,MAX_TYPE>
    // not a problem for one time parser
    static std::unordered_map<std::string, RDataBuilder>& GetBuilders()
    {
        static std::unordered_map<std::string, RDataBuilder> builders;
        return builders;
    }
};

template <typename T>
class CRTPAutoRegistrator {
    virtual void DontOptimizeMyStatic() { std::cout << CRTPAutoRegistrator<T>::registrator; }
    static bool registrator;
};
template <typename T>
bool CRTPAutoRegistrator<T>::registrator = RDataFactory::Register(T::GetDataType(), T::Builder);

class ARData : public RData, CRTPAutoRegistrator<ARData> {
    std::vector<uint8_t> m_data;
    ARData(MessageParser& mp, size_t RDLENGTH)
    {
        if (RDLENGTH != 4)
            throw std::invalid_argument("wrong rdata size for A record");
        m_data = mp.GetRawData(RDLENGTH);
    }

public:
    static const std::string GetDataType() { return "A"; };
    static RData* Builder(MessageParser& mp, size_t RDLENGTH) { return new ARData(mp, RDLENGTH); }

    virtual operator std::string() override
    {
        std::stringstream ss;
        for (size_t i = 0; i < m_data.size(); i++)
            ss << (int)(m_data)[i] << ((i != m_data.size() - 1) ? "." : "");
        return ss.str();
    }
};

class AAAARData : public RData, CRTPAutoRegistrator<AAAARData> {
    std::vector<uint8_t> m_data;
    AAAARData(MessageParser& mp, size_t RDLENGTH)
    {
        if (RDLENGTH != 16)
            throw std::invalid_argument("wrong rdata size for AAAA record");
        m_data = mp.GetRawData(RDLENGTH);
    };

public:
    static const std::string GetDataType() { return "AAAA"; };
    static RData* Builder(MessageParser& mp, size_t RDLENGTH) { return new AAAARData(mp, RDLENGTH); }
    virtual operator std::string() override
    {
        std::stringstream ss;

        ss.setf(std::ios_base::hex, std::ios_base::basefield);
        // could be improved with replacing zeros with :: and remove leading zeros...
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
    DomainRData(MessageParser& mp, size_t RDLENGTH)
    {
        size_t offsetBefore = mp.GetCurrentOffset();

        m_domain = mp.GetDomainName();
        size_t offsetAfter = mp.GetCurrentOffset();

        //  RAII-offset-checker wouldn't work - we couldn't throw from destructor :-(
        if (offsetAfter - offsetBefore != RDLENGTH)
            throw std::invalid_argument("RDLENGTH not equial to domain name");
    }
    virtual operator std::string() override
    {
        return m_domain;
    }
};

class CNAMERData : public DomainRData, CRTPAutoRegistrator<CNAMERData> {
    CNAMERData(MessageParser& mp, size_t RDLENGTH)
        : DomainRData(mp, RDLENGTH)
    {
    }

public:
    static const std::string GetDataType() { return "CNAME"; };
    static RData* Builder(MessageParser& mp, size_t RDLENGTH) { return new CNAMERData(mp, RDLENGTH); }
};
class NSRData : public DomainRData, CRTPAutoRegistrator<NSRData> {
    NSRData(MessageParser& mp, size_t RDLENGTH)
        : DomainRData(mp, RDLENGTH)
    {
    }

public:
    static const std::string GetDataType() { return "NS"; };
    static RData* Builder(MessageParser& mp, size_t RDLENGTH) { return new NSRData(mp, RDLENGTH); }
};
class PTRRData : public DomainRData, CRTPAutoRegistrator<PTRRData> {
    PTRRData(MessageParser& mp, size_t RDLENGTH)
        : DomainRData(mp, RDLENGTH)
    {
    }

public:
    static const std::string GetDataType() { return "PTR"; };
    static RData* Builder(MessageParser& mp, size_t RDLENGTH) { return new PTRRData(mp, RDLENGTH); }
};

class MXRData : public RData, CRTPAutoRegistrator<MXRData> {
    MXRData(MessageParser& mp, size_t RDLENGTH)
    {
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
    static RData* Builder(MessageParser& mp, size_t RDLENGTH) { return new MXRData(mp, RDLENGTH); }

    virtual operator std::string() override
    {
        return std::to_string(m_preference) + " " + m_exchange;
    }
};
class TXTRData : public RData, CRTPAutoRegistrator<TXTRData> {
    std::string m_str;
    TXTRData(MessageParser& mp, size_t RDLENGTH)
    {
        std::vector<uint8_t> raw_data = mp.GetRawData(RDLENGTH);
        m_str = std::string(raw_data.begin(), raw_data.end());
    }

public:
    static const std::string GetDataType() { return "TXT"; };
    static RData* Builder(MessageParser& mp, size_t RDLENGTH) { return new TXTRData(mp, RDLENGTH); }
    virtual operator std::string() override
    {
        return m_str;
    }
};

class SOARData : public RData, CRTPAutoRegistrator<SOARData> {
    std::string m_mname;
    std::string m_rname;
    uint32_t m_serial;
    uint32_t m_refresh;
    uint32_t m_retry;
    uint32_t m_expire;
    uint32_t m_minimum;
    SOARData(MessageParser& mp, size_t RDLENGTH)
    {
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
    static RData* Builder(MessageParser& mp, size_t RDLENGTH) { return new SOARData(mp, RDLENGTH); }

    virtual operator std::string() override
    {
        return m_mname +
               " " + m_rname +
               " " + std::to_string(m_serial) +
               " " + std::to_string(m_refresh) +
               " " + std::to_string(m_retry) +
               " " + std::to_string(m_expire) +
               " " + std::to_string(m_minimum);
    }
};

//BTW, why SRV RR fields order is broken everywhere?
//why TTL class and type are reordered?!
class SRVRData : public RData, CRTPAutoRegistrator<SRVRData> {
    uint16_t m_priority;
    uint16_t m_weight;
    uint16_t m_port;
    std::string m_target;
    SRVRData(MessageParser& mp, size_t RDLENGTH)
    {
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
    static RData* Builder(MessageParser& mp, size_t RDLENGTH) { return new SRVRData(mp, RDLENGTH); }

    virtual operator std::string() override
    {
        return std::to_string(m_priority) + " " + std::to_string(m_weight) + " " + std::to_string(m_port) + " " + m_target;
    }
};

MessageParser::MessageParser(std::vector<uint8_t>&& message)
    : m_offset(0)
    , m_raw_data(message)
{
}

template <typename T>
T MessageParser::Get()
{
    T ret;
    if (m_offset + sizeof(ret) > m_raw_data.size())
        throw std::invalid_argument("out of bound");
    std::memcpy(&ret, m_raw_data.data() + m_offset, sizeof(ret));
    m_offset += sizeof(ret);
    ret = ntoh(ret);
    return ret;
}

header_t
MessageParser::GetHeader()
{
    header_t ret;
    if (m_raw_data.size() < sizeof(uint16_t) * 6) {
        std::string errMsg("could not parse dns header");
        throw std::invalid_argument(errMsg);
    }
    uint8_t* data = m_raw_data.data();

    ret.ID = Get<uint16_t>();

    uint16_t flags = Get<uint16_t>();

    ret.RCODE = flags & 0xF;
    ret.Z = (flags >> 4) & 0x111;
    ret.RA = (flags >> 7) & 0x1;
    ret.RD = (flags >> 8) & 0x1;
    ret.TC = (flags >> 9) & 0x1;
    ret.AA = (flags >> 10) & 0x1;
    ret.Opcode = (flags >> 11) & 0xF;
    ret.QR = flags >> 15;

    ret.QDCOUNT = Get<uint16_t>();
    ret.ANCOUNT = Get<uint16_t>();
    ret.NSCOUNT = Get<uint16_t>();
    ret.ARCOUNT = Get<uint16_t>();

    return ret;
}

std::string
MessageParser::GetDomainName(bool couldBeCompressed)
{
    char domain[MAX_NAME_LENGTH + 1];
    size_t dOffset = 0;
    domain[dOffset] = 0;

    size_t lSize;
    bool compressed = false;

    size_t offset = m_offset;
    uint8_t* data = m_raw_data.data();

    while ((offset < m_raw_data.size()) && ((lSize = data[offset]) != 0)) {
        if ((lSize & 0xC0) == 0xC0) {
            if (!couldBeCompressed)
                throw std::invalid_argument("it shouldn't be compressed"); // rfc-2782...
            if (!compressed)
                m_offset += 1;
            compressed = true;
            if (offset + 1 >= m_raw_data.size())
                throw std::invalid_argument("out of bound");
            offset = ((data[offset] & 0x3f) << 8) | data[offset + 1];
            if (offset >= m_raw_data.size())
                throw std::invalid_argument("out of bound");
        } else {
            offset++;
            if (offset + lSize > m_raw_data.size())
                throw std::invalid_argument("out of bound");
            if (dOffset + lSize + 2 > MAX_NAME_LENGTH)
                throw std::invalid_argument("too long domain name");

            std::memcpy(domain + dOffset, data + offset, lSize);
            offset += lSize;
            dOffset += lSize;

            domain[dOffset] = '.';
            dOffset++;
            domain[dOffset] = 0;

            if (!compressed)
                m_offset = offset;
        }
    }
    m_offset++;
    return domain;
}

question_t
MessageParser::GetQuestion()
{
    question_t ret;

    ret.QNAME = GetDomainName();
    ret.QTYPE = Get<uint16_t>();
    ret.QCLASS = Get<uint16_t>();

    return ret;
}

resource_record_t
MessageParser::GetResourceRecord()
{
    resource_record_t ret;
    ret.NAME = GetDomainName();

    ret.TYPE = Get<uint16_t>();
    ret.CLASS = Get<uint16_t>();
    ret.TTL = Get<uint32_t>();

    ret.RDATA = GetRData(ret.TYPE);

    return ret;
}

std::vector<uint8_t>
MessageParser::GetRawData(size_t length)
{
    if ((m_offset + length) > m_raw_data.size())
        throw std::invalid_argument("out of bound");
    std::vector<uint8_t> ret(
        m_raw_data.begin() + m_offset,
        m_raw_data.begin() + m_offset + length);

    m_offset += length;
    return ret;
}

// https://www.cloudflare.com/learning/dns/dns-records/
// I guess, it's enough to implement commonly-used subset and print hex for other things...
// +AAAA, which is hidden in A.
std::unique_ptr<RData>
MessageParser::GetRData(uint16_t type)
{
    RData* ret;

    uint8_t* data = m_raw_data.data();
    size_t& offset = m_offset;

    uint16_t RDLENGTH = Get<uint16_t>();

    std::string typeName;
    if (types.find(type) != types.end())
        typeName = types.at(type);
    else
        typeName = "unknown(" + std::to_string(type) + ")";

    ret = RDataFactory::BuildRData(typeName, *this, RDLENGTH);

    return std::unique_ptr<RData>(ret);
}

dns_message_t
MessageParser::GetDnsMessage()
{
    dns_message_t ret;
    ret.Header = GetHeader();
    if (ret.Header.QDCOUNT > 0) {
        for (int i = 0; i < ret.Header.QDCOUNT; i++)
            ret.Question.push_back(GetQuestion());
    }
    if (ret.Header.ANCOUNT > 0) {
        for (int i = 0; i < ret.Header.ANCOUNT; i++)
            ret.Answer.push_back(GetResourceRecord());
    }

    if (ret.Header.NSCOUNT > 0) {
        for (int i = 0; i < ret.Header.NSCOUNT; i++)
            ret.Authority.push_back(GetResourceRecord());
    }
    if (ret.Header.ARCOUNT > 0) {
        for (int i = 0; i < ret.Header.ARCOUNT; i++)
            ret.Additional.push_back(GetResourceRecord());
    }
    return ret;
}

std::ostream& operator<<(std::ostream& os, header_t h)
{

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
    flagss << (h.QR ? " qr" : "") << (h.AA ? " aa" : "") << (h.TC ? " tc" : "") << (h.RD ? " rd" : "") << (h.RA ? " ra" : "");
    std::string flags = flagss.str();

    os << ";; ->>HEADER<<- opcode: " << opcode << "; status: " << status << "; id: " << h.ID << std::endl;
    os << ";; Flags:" << flags;
    os << "; QUERY: " << h.QDCOUNT << "; ANSWER: " << h.ANCOUNT << "; AUTHORITY: " << h.NSCOUNT << "; ADDITIONAL: " << h.ARCOUNT;
    return os;
};

std::ostream& operator<<(std::ostream& os, question_t q)
{
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

std::string print_rdata(uint16_t, const void*, uint16_t);

std::ostream& operator<<(std::ostream& os, const std::unique_ptr<RData>& d)
{
    os << (std::string)*d;
    return os;
}

std::ostream& operator<<(std::ostream& os, const resource_record_t& r)
{
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

    os << r.NAME << "\t\t" << r.TTL << "\t" << cl << "\t" << type << "\t" << r.RDATA;
    return os;
}

std::ostream& operator<<(std::ostream& os, const dns_message_t& d)
{
    os << d.Header << std::endl
       << std::endl;
    if (d.Question.size()) {
        os << ";; QUESTION SECTION:";
        for (const auto& it : d.Question)
            os << std::endl
               << it;
    }
    if (d.Answer.size()) {
        std::cout << std::endl;
        std::cout << std::endl
                  << ";; ANSWER SECTION:";
        for (const auto& it : d.Answer)
            os << std::endl
               << it;
    }
    if (d.Authority.size()) {
        std::cout << std::endl;
        std::cout << std::endl
                  << ";; AUTHORATIVE NAMESERVERS SECTION:";
        for (const auto& it : d.Authority)
            os << std::endl
               << it;
    }
    if (d.Additional.size()) {
        std::cout << std::endl;
        std::cout << std::endl
                  << ";; ADDITIONAL RECORDS SECTION:";
        for (const auto& it : d.Additional)
            os << std::endl
               << it;
    }
    return os;
}

uint8_t parse_raw(const char* buf)
{
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

std::vector<uint8_t>
parse_input_string(std::string str)
{

    size_t strSize = str.size();
    if (
        strSize % 4 != 2 || str[0] != '"' || str[strSize - 1] != '"') {
        std::string errMsg;
        errMsg += "\"";
        errMsg += str;
        errMsg += "\" is not hex formatted string";
        throw std::invalid_argument(errMsg);
    }

    const char* strCStr = str.c_str();
    std::vector<uint8_t> ret(strSize / 4);
    for (size_t i = 0; i < strSize / 4; i++) {
        ret[i] = parse_raw(strCStr + 1 + 4 * i);
    }
    return ret;
}

int main()
{
    /* Enter your code here. Read input from STDIN. Print output to STDOUT */
    try {
        std::vector<uint8_t> raw_data;
        while (std::cin.good()) {
            raw_data.reserve(UDP_SIZE_LIMIT);
            std::string input;

            std::cin >> input;

            if ((input.size() == 1 && input[0] == '\\') || input.size() == 0)
                continue; // copy-paste to terminal from hackerrank add empty lines to input, so ignore 0-sized strings

            auto raw_string_data = parse_input_string(input);

            raw_data.insert(raw_data.end(), raw_string_data.begin(), raw_string_data.end());
        }

        MessageParser mp(std::move(raw_data));

        dns_message_t dm = mp.GetDnsMessage();
        std::cout << dm << std::endl;
    } catch (std::invalid_argument& e) {
        std::cout << "could not parse input message" << e.what();
        throw;
    }

    return 0;
}
