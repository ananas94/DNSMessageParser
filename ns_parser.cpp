#include <map>
#include <set>
#include <list>
#include <cmath>
#include <ctime>
#include <deque>
#include <queue>
#include <stack>
#include <string>
#include <bitset>
#include <cstdio>
#include <limits>
#include <vector>
#include <climits>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <numeric>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <unordered_map>
#include <cstdint>

const size_t UDP_SIZE_LIMIT=512;
const size_t MAX_NAME_LENGTH=255;

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

struct resource_record_t{
	std::string NAME;
	uint16_t TYPE;
	uint16_t CLASS;
	uint32_t TTL;
	uint16_t RDLENGTH;
	const void *RDATA;	
};

struct dns_message_t{
	header_t Header;
	question_t *Question;
	resource_record_t *Answer;
	resource_record_t *Authority;
	resource_record_t *Additional;
};	


//could be linux/windows function, but platform is unspecified, so make own implementations
// TODO: add ifdef
uint16_t
ntohs(uint16_t net)
{
	uint16_t ret = (net & 0xff) << 8 | (net & 0xff00) >> 8;
	return ret;

}
uint32_t
ntohl(uint32_t net)
{
	uint32_t ret = (net & 0xff000000) >> 24 | (net & 0xff0000) >> 8 | (net & 0xff00) << 8 | (net & 0xff) <<24;
	return ret;
}


class MessageParser
{
	public:
		MessageParser(std::vector<uint8_t> message);
		dns_message_t GetDnsMessage();
	//private:
		header_t GetHeader();
		question_t GetQuestion();
		resource_record_t GetRecrod();
		std::string GetDomainName(bool couldBeCompressed=true);

	private:
		size_t m_offset;
		std::vector<uint8_t> m_raw_data;
};

//TODO: should I add move semantic here?
MessageParser::MessageParser(std::vector<uint8_t> message): 
	m_raw_data(message), m_offset(0)
{}

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

	std::memcpy(&ret.ID, data, sizeof(ret.ID));
	ret.ID = ntohs(ret.ID);
	this->m_offset =+ sizeof(ret.ID);

	uint16_t flags;
	std::memcpy(&flags, data + this->m_offset , sizeof(flags));
	flags = ntohs(flags);

	ret.RCODE = flags & 0xF;
	ret.Z = (flags >> 4) & 0x111;
	ret.RA = (flags >> 7) & 0x1;
	ret.RD = (flags >> 8) & 0x1;
	ret.TC = (flags >> 9) & 0x1;
	ret.AA = (flags >> 10) & 0x1;
	ret.Opcode = (flags >> 11) & 0xF;
	ret.QR = flags >> 15;

	this->m_offset += sizeof(flags);

	std::memcpy(&ret.QDCOUNT, data + this->m_offset, sizeof(ret.QDCOUNT));
	ret.QDCOUNT = ntohs(ret.QDCOUNT);
	this->m_offset += sizeof(ret.QDCOUNT);

	std::memcpy(&ret.ANCOUNT, data + this->m_offset, sizeof(ret.ANCOUNT));
	ret.ANCOUNT = ntohs(ret.ANCOUNT);
	this->m_offset += sizeof(ret.ANCOUNT);

	std::memcpy(&ret.NSCOUNT, data + this->m_offset, sizeof(ret.NSCOUNT));
	ret.NSCOUNT = ntohs(ret.NSCOUNT);
	this->m_offset += sizeof(ret.NSCOUNT);

	std::memcpy(&ret.ARCOUNT, data + this->m_offset, sizeof(ret.ARCOUNT));
	ret.ARCOUNT = ntohs(ret.ARCOUNT);
	this->m_offset += sizeof(ret.ARCOUNT);

	return ret;
}


std::string
MessageParser::GetDomainName(bool couldBeCompressed )
{
	char domain[ MAX_NAME_LENGTH + 1];	
	size_t dOffset = 0;
	domain[dOffset]=0;


	size_t lSize;
	bool   compressed = false;
	
	size_t offset = this->m_offset;
	uint8_t *data = this->m_raw_data.data();

	while ( (lSize = data[offset]) != 0 )
	{
		if ( (lSize & 0xC0) == 0xC0)
		{
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

	ret.QNAME = this->GetDomainName();
	
	uint8_t *data = this->m_raw_data.data();

	std::memcpy(&ret.QTYPE, data + this->m_offset, sizeof(ret.QTYPE));
	ret.QTYPE = ntohs(ret.QTYPE);
	this->m_offset += sizeof(ret.QTYPE);


	std::memcpy(&ret.QCLASS, data + this->m_offset, sizeof(ret.QCLASS));
	ret.QCLASS = ntohs(ret.QCLASS);
	this->m_offset += sizeof(ret.QCLASS);

	return ret;
}

resource_record_t
MessageParser::GetRecrod()
{
	resource_record_t ret;
	/*
	std::string NAME;
	uint16_t TYPE;
	uint16_t CLASS;
	uint32_t TTL;
	uint16_t RDLENGTH;
	void *RDATA;	
	*/
	ret.NAME = this->GetDomainName();
	//dOffset = parse_name(domain, sizeof(domain), buff, offset, size); //TODO: see parse_question

	uint8_t *data = this->m_raw_data.data();	
	size_t &offset = this->m_offset;

	std::memcpy(&ret.TYPE, data + offset, sizeof(ret.TYPE));   //TODO: make function.. probably with pointer to member... probably template for i32
	ret.TYPE = ntohs(ret.TYPE);
	offset += sizeof(ret.TYPE);

	std::memcpy(&ret.CLASS, data + offset, sizeof(ret.CLASS));
	ret.CLASS = ntohs(ret.CLASS);
	offset += sizeof(ret.CLASS);

	std::memcpy(&ret.TTL, data + offset, sizeof(ret.TTL));
	ret.TTL = ntohl(ret.TTL);  // maybe ntoh() not C-like?
	offset += sizeof(ret.TTL);


	std::memcpy(&ret.RDLENGTH, data + offset, sizeof(ret.RDLENGTH));
	ret.RDLENGTH = ntohs(ret.RDLENGTH);
	offset += sizeof(ret.RDLENGTH);

	ret.RDATA = data + offset;
	offset += ret.RDLENGTH;

	return ret;

}

std::ostream& operator<<(std::ostream& os, header_t h)
{

/*
;; ->>HEADER<<- opcode: QUERY; status: NOERROR; id: 28028
;; Flags: qr rd ra; QUERY: 1; ANSWER: 1; AUTHORITY: 0; ADDITIONAL: 0
*/
	os << ";; ->>HEADER<<- opcode: " << h.Opcode << "; status: " << h.RCODE << "; id: " <<h.ID << std::endl;
	os << ";; Flags: qr " << h.QR << "AA: "<< h.AA << " TC " <<h.TC<<" RD "<<h.RD<<" RA " <<h.RA <<" Z " <<h.Z <<std::endl;
	os << "QUER " <<h.QDCOUNT << " AN "<< h.ANCOUNT <<" NS " << h.NSCOUNT << " AR " << h.ARCOUNT << std::endl;
	return os;
};





//TODO: make std::cout do it 
void
print_question(const question_t &q)
{
/*
    ;; QUESTION SECTION:
    ;; example.com.			IN	A
*/
	std::cout << q.QNAME << "\t\t\t" << q.QCLASS << "\t"<< q.QTYPE <<std::endl;
}



resource_record_t
parse_record(const uint8_t * buff, size_t offset, size_t size, size_t &rOffset)
{
	/*
	resource_record_t ret;
	/*
	std::string NAME;
	uint16_t TYPE;
	uint16_t CLASS;
	uint32_t TTL;
	uint16_t RDLENGTH;
	void *RDATA;	
	*/
	/*
	char domain[ MAX_NAME_LENGTH + 1];	
	size_t dOffset = 0;
	domain[dOffset]=0;
	//dOffset = parse_name(domain, sizeof(domain), buff, offset, size); //TODO: see parse_question

	ret.NAME = domain;

	std::memcpy(&ret.TYPE, buff + dOffset, sizeof(ret.TYPE));   //TODO: make function.. probably with pointer to member... probably template for i32
	ret.TYPE = ntohs(ret.TYPE);
	dOffset += sizeof(ret.TYPE);

	std::memcpy(&ret.CLASS, buff + dOffset, sizeof(ret.CLASS));
	ret.CLASS = ntohs(ret.CLASS);
	dOffset += sizeof(ret.CLASS);

	std::memcpy(&ret.TTL, buff + dOffset, sizeof(ret.TTL));
	ret.TTL = ntohl(ret.TTL);  // maybe ntoh() not C-like?
	dOffset += sizeof(ret.TTL);


	std::memcpy(&ret.RDLENGTH, buff + dOffset, sizeof(ret.RDLENGTH));
	ret.RDLENGTH = ntohs(ret.RDLENGTH);
	dOffset += sizeof(ret.RDLENGTH);

	ret.RDATA = buff + dOffset;
	dOffset += ret.RDLENGTH;

	return ret;
	*/
};

// https://www.cloudflare.com/learning/dns/dns-records/
// https://en.wikipedia.org/wiki/List_of_DNS_record_types
// I guess, it's enough to implement commonly-used subset and print hex for other things...
// wait... where is AAAA record?
const char* print_rdata(uint16_t,const void *,uint16_t) { return "";}

//TODO: make std::cout do it 
void
print_resourse_record(resource_record_t r)
{
	/*
		example.com.		76391	IN	A	93.184.216.34
	   */
	std::cout << r.NAME << "\t\t" << r.TTL << "\t" << r.CLASS << "\t" << r.TYPE << "\t" << print_rdata(r.TYPE, r.RDATA, r.RDLENGTH) << std::endl;
}



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
		std::string errMsg; //TODO: on c++20 std::format me 
		errMsg+="\"";
		errMsg+=str;
		errMsg+="\" is not hex formatted string";
		throw std::invalid_argument(errMsg);
	}

	const char *strCStr = str.c_str();
	std::vector<uint8_t> ret(strSize/4);
	for (int i = 0; i<strSize/4; i++)
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

			if (input.size() == 1 && input[0] == '\\' || input.size()==0 ) continue; // copy-paste to terminal from hackerrank add empty lines to input, so ignore 0-sized strings

			auto raw_string_data = parse_input_string(input);

			raw_data.insert(raw_data.end(), raw_string_data.begin(), raw_string_data.end());
		}



		MessageParser mp(raw_data);

		header_t header = mp.GetHeader();
		std::cout << header;
		if (header.QDCOUNT > 0 )  //TODO: check if RFC forbid QDCOUNT == 0
		{
			std::cout << ";; QUESTION SECTION:"<<std::endl;
			for (int i=0; i< header.QDCOUNT; i++) 
			{
				question_t question = mp.GetQuestion();
				print_question(question);
			}
		}
		if (header.ANCOUNT > 0 )  //TODO: check if RFC forbid QDCOUNT == 0
		{
			std::cout << ";; ANSWER SECTION:"<<std::endl;
			for (int i=0; i< header.ANCOUNT; i++) 
			{
				resource_record_t record = mp.GetRecrod();
				print_resourse_record(record);
			}
		}
	

		/*
		size_t qOffset = 0;
		if (header.QDCOUNT > 0 )  //TODO: check if RFC forbid QDCOUNT == 0
		{
			std::cout << ";; QUESTION SECTION:"<<std::endl;
			for (int i=0; i< header.QDCOUNT; i++) 
			{
				question_t question = parse_question(raw_data.data(), qOffset + headerOffset, raw_data.size(), qOffset);
				print_question(question);
			}
		}
		size_t resourceRecordOffset = 0;
		if (header.ANCOUNT > 0 )  //TODO: check if RFC forbid QDCOUNT == 0
		{
			std::cout << ";; ANSWER SECTION:"<<std::endl;
			for (int i=0; i< header.ANCOUNT; i++) 
			{
				resource_record_t record = parse_record(raw_data.data(), qOffset + resourceRecordOffset + headerOffset, raw_data.size(), resourceRecordOffset);
				print_resourse_record(record);
			}
		}
		if (header.NSCOUNT > 0 )  //TODO: check if RFC forbid QDCOUNT == 0
		{
			std::cout << ";; AUTHORATIVE NAMESERVERS SECTION:"<<std::endl;
			for (int i=0; i< header.NSCOUNT; i++) 
			{
				resource_record_t record = parse_record(raw_data.data(), qOffset + resourceRecordOffset + headerOffset, raw_data.size(), resourceRecordOffset);
				print_resourse_record(record);
			}
		}
		if (header.ARCOUNT > 0 )  //TODO: check if RFC forbid QDCOUNT == 0
		{
			std::cout << ";; ADDITIONAL RECORDS SECTION:"<<std::endl;
			for (int i=0; i< header.ARCOUNT; i++) 
			{
				resource_record_t record = parse_record(raw_data.data(), qOffset + resourceRecordOffset + headerOffset, raw_data.size(), resourceRecordOffset);
				print_resourse_record(record);
			}
		}
		*/

	}
	catch (std::invalid_argument e)
	{
		std::cout << e.what();
		throw;
	}
	
    return 0;
}
