#include <string>
#include <cstdio>
#include <vector>
#include <cstring>
#include <sstream>
#include <iostream>
#include <unordered_map>
#include <cstdint>
#include <memory>
#include <iomanip>

const size_t UDP_SIZE_LIMIT=512;
const size_t MAX_NAME_LENGTH=255;

const std::unordered_map<uint16_t,std::string> types = {
	{1, "A"},  
	{2, "NS"}, 
	{3, "MD"},   
	{4, "MF"}, 
	{5, "CNAME"}, 
	{6, "SOA"}, 
	{7, "MB"},  
	{8, "MG"},  
	{9, "MR"}, 
	{10, "NULL"},
	{11, "WKS"},
	{12, "PTR"},
	{13, "HINFO"}, 
	{14, "MINFO"}, 
	{15, "MX"}, 
	{16, "TXT"},

	{28, "AAAA"},

	{252, "AXFR"},   //QTYPES
	{253, "MAILB"},
	{254, "MAILA"},
	{255, "*"}
};

const std::unordered_map<uint16_t,std::string> classes = {
	{1,   "IN"},
	{2,   "CS"},
	{3,   "CH"},
	{4,   "HS"},
	{255, "*"},   //QCLASS
};


const std::unordered_map<uint16_t,std::string> opcodes = {
	{0,   "QUERY"},
	{1,   "IQUERY"},
	{2,   "STATUS"}
};


const std::unordered_map<uint16_t,std::string> statuses = {
	{0,   "NOERROR"},
	{1,   "FORMATERROR"},
	{2,   "SERVERFAILURE"},
	{3,   "NAMEERROR"},
	{4,   "NOTIMPLEMENTED"},
	{5,   "REFUSED"},

};

struct header_t{
	uint16_t ID;
 	//not a real thing. could be usefull if we stuck to big-endianness, platform, compiller and sure about paddings 
	uint16_t QR:1,Opcode:4,AA:1,TC:1,RD:1,RA:1,Z:1,RCODE:4;
	uint16_t QDCOUNT;
	uint16_t ANCOUNT;
	uint16_t NSCOUNT;
	uint16_t ARCOUNT;
};

struct question_t{
	std::string QNAME;
	uint16_t QTYPE;
	uint16_t QCLASS;
};

class RData;
struct resource_record_t{
	std::string NAME;
	uint16_t TYPE;
	uint16_t CLASS;
	uint32_t TTL;
	std::unique_ptr<RData> RDATA;
};

struct dns_message_t{
	header_t Header;
	std::vector<question_t> Question;
	std::vector<resource_record_t> Answer;
	std::vector<resource_record_t> Authority;
	std::vector<resource_record_t> Additional;
};	




//could be linux/windows C-functions, but platform is unspecified, so make own implementations
// TODO: add ifdef
uint16_t
ntoh(uint16_t net)
{
	uint16_t ret = (net & 0xff) << 8 | (net & 0xff00) >> 8;
	return ret;

}
uint32_t
ntoh(uint32_t net)
{
	uint32_t ret = (net & 0xff000000) >> 24 | (net & 0xff0000) >> 8 | (net & 0xff00) << 8 | (net & 0xff) <<24;
	return ret;
}


class MessageParser
{
	public:
		MessageParser(std::vector<uint8_t>&& message);
		dns_message_t GetDnsMessage();
	private:
		header_t GetHeader();
		question_t GetQuestion();
		resource_record_t GetResourceRecord();
		std::unique_ptr<RData> GetRData(uint16_t type);
		std::string GetDomainName(bool couldBeCompressed=true);
		template<typename T> T Get();
	private:
		size_t m_offset;
		std::vector<uint8_t> m_raw_data;
};

class RData
{
	public:
	virtual operator std::string() = 0;
	virtual ~RData() =default;
};


class GenericRData: public RData
{
	protected:
		std::vector<uint8_t> m_data;
	public:
		GenericRData(std::vector<uint8_t> &&data): m_data(data) {}
		virtual operator std::string()
		{
			std::stringstream ss;
			ss << "unknown rdata(" << this->m_data.size() <<") hex: [";
			ss.setf(std::ios_base::hex, std::ios_base::basefield);
			ss.setf(std::ios_base::showbase);
			for (const uint8_t &it : m_data)
				ss << (int) (it) << " ";

			ss.unsetf(std::ios_base::hex);
			ss<< "]";

			return ss.str();
		}
};


class ARData: public RData
{
	std::vector<uint8_t> m_data;
	public:
		ARData(std::vector<uint8_t> &&data): m_data(data) 
		{
			if ( this->m_data.size() != 4 ) throw std::invalid_argument("wrong rdata size for A record");
		}
		virtual operator std::string() override
		{
			std::stringstream ss;
			for (size_t i=0; i < this->m_data.size(); i++)
				ss << (int) (this->m_data)[i] <<( (i!=this->m_data.size()-1) ? "." : "");
			return ss.str();
		}
};

class AAAARData: public RData
{
	std::vector<uint8_t> m_data;
	public:
		AAAARData(std::vector<uint8_t> &&data): m_data(data) 
		{
			if ( this->m_data.size() != 16 )  throw std::invalid_argument("wrong rdata size for AAAA record");
		};
		virtual operator std::string() override
		{
			std::stringstream ss;

			ss.setf(std::ios_base::hex, std::ios_base::basefield);
			// could be improved with replacing zeros with :: and remove leading zeros...
			for (size_t i=0; i <  this->m_data.size(); i+=2)
				ss << std::setw(2) << std::setfill('0') << (int) (this->m_data)[i] 
				   << std::setw(2) << std::setfill('0') << (int) (this->m_data)[i+1]
			   	   <<( (i!=this->m_data.size()  -2) ? ":" : "");

			ss.unsetf(std::ios_base::hex);
			return ss.str();
		}
};

class CNAMERData: public RData
{
	std::string m_domain;
	public:
		CNAMERData(std::string domain ): m_domain(domain) {};
		virtual operator std::string() override
		{
			return m_domain;
		}
};

class MXRData: public RData
{
	std::string m_domain;
	uint16_t m_preference;
	public:
		MXRData ( std::string domain, uint16_t preference) :  m_domain(domain), m_preference(preference) {}
		virtual operator std::string() override
		{
			return std::to_string(m_preference) + " " + m_domain;
		}
};
class TXTRData: public RData
{
	std::string m_str;
	public:
	TXTRData(std::string&& str) : m_str(str) {};
	virtual operator std::string() override
	{
		return m_str;
	}
};

class NSRData: public RData
{
	std::string m_domain;
	public:
		NSRData(const void* d, size_t s, std::string domain ): m_domain(domain) {};
		virtual operator std::string() override
		{
			return m_domain;
		}
};


MessageParser::MessageParser(std::vector<uint8_t>&& message): 
	 m_offset(0), m_raw_data(message)
{}


template<typename T>
T MessageParser::Get()
{
	T ret;
	if ( this->m_offset + sizeof(ret) > this->m_raw_data.size() ) throw std::invalid_argument("out of bound");
	std::memcpy(&ret, this->m_raw_data.data() + this->m_offset, sizeof(ret));
	this->m_offset += sizeof(ret);
	ret= ntoh(ret);
	return ret;
}


header_t
MessageParser::GetHeader()
{
	header_t ret;
	if (this->m_raw_data.size() < sizeof(uint16_t) * 6)
	{
		std::string errMsg("could not parse dns header");
		throw std::invalid_argument(errMsg);

	}
	uint8_t *data = this->m_raw_data.data();

	ret.ID = this->Get<uint16_t>();


	uint16_t flags =this->Get<uint16_t>();

	ret.RCODE = flags & 0xF;
	ret.Z = (flags >> 4) & 0x111;
	ret.RA = (flags >> 7) & 0x1;
	ret.RD = (flags >> 8) & 0x1;
	ret.TC = (flags >> 9) & 0x1;
	ret.AA = (flags >> 10) & 0x1;
	ret.Opcode = (flags >> 11) & 0xF;
	ret.QR = flags >> 15;


	ret.QDCOUNT =this->Get<uint16_t>();
	ret.ANCOUNT =this->Get<uint16_t>();
	ret.NSCOUNT =this->Get<uint16_t>();
	ret.ARCOUNT =this->Get<uint16_t>();

	return ret;
}


std::string
MessageParser::GetDomainName(bool couldBeCompressed)
{
	char domain[ MAX_NAME_LENGTH + 1];	
	size_t dOffset = 0;
	domain[dOffset]=0;

	size_t lSize;
	bool   compressed = false;
	
	size_t offset =  this->m_offset;
	uint8_t *data = this->m_raw_data.data();

	while ( (lSize = data[offset]) != 0 )
	{
		if ( (lSize & 0xC0) == 0xC0)
		{
			if (!couldBeCompressed) throw std::invalid_argument("catch you"); // once kubernetes send srv with compression...
			if (!compressed )
				this->m_offset+=1; 
			compressed = true;
			offset = ((data[offset] & 0x3f) << 8 ) | data[offset+1];
		}
		else
		{
			offset++;
			//TODO: check domain and raw_data size
			std::memcpy(domain+dOffset, data+offset, lSize);
			offset+=lSize;
			dOffset+=lSize;

			domain[dOffset] = '.'; 
			dOffset++;
			domain[dOffset]=0;

			if ( !compressed )
				this->m_offset=offset;
		}

	}
	this->m_offset++;
	return domain;
}

question_t
MessageParser::GetQuestion()
{
	question_t ret;

	ret.QNAME  = this->GetDomainName();
	ret.QTYPE  = this->Get<uint16_t>();
	ret.QCLASS = this->Get<uint16_t>();

	return ret;
}

resource_record_t
MessageParser::GetResourceRecord()
{
	resource_record_t ret;
	ret.NAME = this->GetDomainName();

	ret.TYPE  = this->Get<uint16_t>();
	ret.CLASS = this->Get<uint16_t>();
	ret.TTL   = this->Get<uint32_t>();

	ret.RDATA = this->GetRData(ret.TYPE);

	return ret;
}

// https://www.cloudflare.com/learning/dns/dns-records/
// I guess, it's enough to implement commonly-used subset and print hex for other things...
// wait... where is AAAA record? (in A record)
std::unique_ptr<RData>
MessageParser::GetRData(uint16_t type)
{
	RData *ret;

	uint8_t *data = this->m_raw_data.data();	
	size_t &offset = this->m_offset;

	uint16_t RDLENGTH = this->Get<uint16_t>();
	if ( offset + RDLENGTH > this->m_raw_data.size() ) throw std::invalid_argument("out of bound");

	void *RDATA = data + offset;
	
//https://www.cppstories.com/2018/02/factory-selfregister/
// probably, not worth it. looks like clang fail to do this

// TODO: enum
	if (type == 1)
	{
		ret =	new ARData(
			       	std::vector<uint8_t>(
					this->m_raw_data.begin() + this->m_offset,
				      	this->m_raw_data.begin() + this->m_offset + RDLENGTH )
			);
		offset += RDLENGTH;
	}
	else if (type == 28)
	{
		ret =	new AAAARData(
			       	std::vector<uint8_t>(
					this->m_raw_data.begin() + this->m_offset,
				      	this->m_raw_data.begin() + this->m_offset + RDLENGTH )
			);
		offset += RDLENGTH;
	}
	else if (type == 5)
	{
		std::string cname = this->GetDomainName();       
		ret = new CNAMERData(cname);
	}
	else if (type == 15)
	{
		uint16_t PREFERENCE = this->Get<uint16_t>();
		std::string EXCHANGE = this->GetDomainName();       
		ret = new MXRData(EXCHANGE, PREFERENCE);
	}
	else if (type == 16) 
	{
		ret = new TXTRData( std::string((const char*)RDATA,RDLENGTH) );
		offset += RDLENGTH;
	} 
	else if (type == 2)
	{
		std::string cname = this->GetDomainName();       
		ret = new NSRData(RDATA, RDLENGTH, cname);
	}
	else
	{
		ret =	new GenericRData(
			       	std::vector<uint8_t>(
					this->m_raw_data.begin() + this->m_offset,
				      	this->m_raw_data.begin() + this->m_offset + RDLENGTH )
			);
		offset += RDLENGTH;
	}
	return std::unique_ptr<RData>(ret);
}



//TODO: move raw_data ownership to dns_message
dns_message_t
MessageParser::GetDnsMessage()
{
	dns_message_t ret;
	ret.Header = this->GetHeader();
	if (ret.Header.QDCOUNT > 0 )  
	{
		for (int i=0; i< ret.Header.QDCOUNT; i++) 
			ret.Question.push_back( this->GetQuestion() );
	}
	if (ret.Header.ANCOUNT > 0 )  
	{
		for (int i=0; i< ret.Header.ANCOUNT; i++) 
			ret.Answer.push_back( this->GetResourceRecord() ) ;
	}
	
	if (ret.Header.NSCOUNT > 0 )  
	{
		for (int i=0; i< ret.Header.NSCOUNT; i++) 
			ret.Authority.push_back( this->GetResourceRecord()) ;
	}
	if (ret.Header.ARCOUNT > 0 )  
	{
		for (int i=0; i< ret.Header.ARCOUNT; i++) 
			ret.Additional.push_back( this->GetResourceRecord()) ;
	}
	return ret;
}

//------------------------------------------------
// output methods

std::ostream& operator<<(std::ostream& os, header_t h)
{

/*
;; ->>HEADER<<- opcode: QUERY; status: NOERROR; id: 28028
;; Flags: qr rd ra; QUERY: 1; ANSWER: 1; AUTHORITY: 0; ADDITIONAL: 0
*/
	std::string opcode;
	if ( opcodes.find(h.Opcode) != opcodes.end() )
		opcode = opcodes.at(h.Opcode);
	else
		opcode ="unknown("+ std::to_string(h.Opcode) +")";

	std::string status;
	if ( statuses.find(h.RCODE) != statuses.end() )
		status = statuses.at(h.RCODE);
	else
		status ="unknown("+ std::to_string(h.RCODE) +")";
	
	std::stringstream flagss;
	flagss << (h.QR ? " qr" : "") << ( h.AA ? " aa" : "")  << (h.TC ? " tc" : "") << (h.RD ? " rd" : "") << (h.RA ? " ra" : "");
	std::string flags = flagss.str();
	
	
	os << ";; ->>HEADER<<- opcode: " << opcode << "; status: " << status << "; id: " <<h.ID << std::endl;
	os << ";; Flags:" << flags;
	os << "; QUERY " <<h.QDCOUNT << "; ANSWER "<< h.ANCOUNT <<"; AUTHORITY " << h.NSCOUNT << "; ADDITIONAL " << h.ARCOUNT;
	return os;
};



std::ostream& operator<<(std::ostream& os, question_t q)
{
/*
    ;; QUESTION SECTION:
    ;; example.com.			IN	A
*/
	std::string cl;
	std::string type;

	if ( classes.find(q.QCLASS) != classes.end() )
		cl = classes.at(q.QCLASS);
	else
		cl ="unknown("+ std::to_string(q.QCLASS) +")";
	
	if ( types.find(q.QTYPE) != types.end() )
		type = types.at(q.QTYPE);
	else
		type ="unknown("+ std::to_string(q.QTYPE)+ ")";

	os <<";; " << q.QNAME << "\t\t\t" << cl << "\t"<< type ;
	return os;
}

std::string print_rdata(uint16_t,const void *,uint16_t);


std::ostream& operator<<(std::ostream& os, const std::unique_ptr<RData>& d)
{
	os << ( std::string) *d;
	return os;
}


std::ostream& operator<<(std::ostream& os, const resource_record_t& r)
{
	/*
;; ANSWER SECTION:
example.com.		76391	IN	A	93.184.216.34
	 */

	std::string cl;
	std::string type;

	if ( classes.find(r.CLASS) != classes.end() )
		cl = classes.at(r.CLASS);
	else
		cl ="unknown("+ std::to_string(r.CLASS) +")";
	
	if ( types.find(r.TYPE) != types.end() )
		type = types.at(r.TYPE);
	else
		type ="unknown("+ std::to_string(r.TYPE)+ ")";


	os << r.NAME << "\t\t" << r.TTL << "\t" << cl << "\t" << type << "\t" <<  r.RDATA;
	return os;
}



std::ostream& operator<<(std::ostream& os, const dns_message_t& d)
{
	os << d.Header << std::endl;
	if (d.Question.size() ) 
	{
		os << ";; QUESTION SECTION:";
		for (const auto& it : d.Question )
			os << std::endl <<it ;
	}
	if (d.Answer.size() ) 
	{
		std::cout <<std::endl << ";; ANSWER SECTION:";
		for (const auto& it : d.Answer )
			os << std::endl << it ;
	}
	if (d.Authority.size() ) 
	{
		std::cout <<std::endl << ";; AUTHORATIVE NAMESERVERS SECTION:";
		for (const auto& it : d.Authority )
			os << std::endl <<it ;
	}
	if (d.Additional.size() ) 
	{
		std::cout <<std::endl << ";; ADDITIONAL RECORDS SECTION:";
		for (const auto& it : d.Additional )
			os << std::endl <<it ; 
	}
	return os;
}





//-------------------------------------------------------------------------------
// functions to handle input

uint8_t parse_raw(const char *buf)
{
	unsigned int uintVal;
	if (sscanf(buf,"\\x%2x", &uintVal) != 1)
	{
		std::string errMsg;
		errMsg+="\"";
		errMsg+=buf;
		errMsg+="\" could not be parsed as hex";
		throw std::invalid_argument(errMsg);
	}
	return uintVal;
}

std::vector<uint8_t>
parse_input_string(std::string str)
{

	size_t strSize = str.size();
	if (
		strSize %4 != 2 ||
		str[0] != '"' || 
	       	str[strSize-1] != '"'   
	   )  
	{
		std::string errMsg; 
		errMsg+="\"";
		errMsg+=str;
		errMsg+="\" is not hex formatted string";
		throw std::invalid_argument(errMsg);
	}

	const char *strCStr = str.c_str();
	std::vector<uint8_t> ret(strSize/4);
	for (size_t i = 0; i < strSize / 4; i++)
	{
		ret[i] = parse_raw(strCStr + 1 + 4*i);
	}
	return ret;
}

int main() {
	/* Enter your code here. Read input from STDIN. Print output to STDOUT */
	try{
		std::vector<uint8_t> raw_data;
		while (std::cin.good())
		{
			raw_data.reserve(UDP_SIZE_LIMIT);
			std::string input;

			std::cin >> input;

			if ( (input.size() == 1 && input[0] == '\\') ||
			     input.size()==0 ) continue; // copy-paste to terminal from hackerrank add empty lines to input, so ignore 0-sized strings

			auto raw_string_data = parse_input_string(input);

			raw_data.insert(raw_data.end(), raw_string_data.begin(), raw_string_data.end());
		}


		MessageParser mp(std::move(raw_data));

		dns_message_t dm = mp.GetDnsMessage();
		std::cout << dm<< std::endl;
	}
	catch (std::invalid_argument& e)
	{
		std::cout << e.what();
		throw;
	}
	
	return 0;
}
