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
	uint16_t QR:1,Opcode:4,AA:1,TC:1,RD:1,RA:1,Z:1,RCODE:4; //not a real thing. could be usefull if we stuck to big-endianness, platform, compiller and sure about paddings 
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

struct dns_message{
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

header_t 
parse_header(const uint8_t *data, const size_t size)
{
	header_t ret;
	if (size < sizeof(uint16_t) * 6)
	{
		std::string errMsg("could not parse dns header");
		throw std::invalid_argument(errMsg);

	}
	std::memcpy(&ret.ID, data, sizeof(ret.ID));
	ret.ID = ntohs(ret.ID);
	size_t offset = sizeof(ret.ID);

	uint16_t flags;
	std::memcpy(&flags, data + offset , sizeof(flags));
	flags = ntohs(flags);

	ret.RCODE = flags & 0xF;
	ret.Z = (flags >> 4) & 0x111;
	ret.RA = (flags >> 7) & 0x1;
	ret.RD = (flags >> 8) & 0x1;
	ret.TC = (flags >> 9) & 0x1;
	ret.AA = (flags >> 10) & 0x1;
	ret.Opcode = (flags >> 11) & 0xF;
	ret.QR = flags >> 15;

	offset += sizeof(flags);

	std::memcpy(&ret.QDCOUNT, data + offset, sizeof(ret.QDCOUNT));
	ret.QDCOUNT = ntohs(ret.QDCOUNT);
	offset += sizeof(ret.QDCOUNT);

	std::memcpy(&ret.ANCOUNT, data + offset, sizeof(ret.ANCOUNT));
	ret.ANCOUNT = ntohs(ret.ANCOUNT);
	offset += sizeof(ret.ANCOUNT);

	std::memcpy(&ret.NSCOUNT, data + offset, sizeof(ret.NSCOUNT));
	ret.NSCOUNT = ntohs(ret.NSCOUNT);
	offset += sizeof(ret.NSCOUNT);

	std::memcpy(&ret.ARCOUNT, data + offset, sizeof(ret.ARCOUNT));
	ret.ARCOUNT = ntohs(ret.ARCOUNT);
	offset += sizeof(ret.ARCOUNT);

	return ret;
}

//TODO: make std::cout do it 
void print_header(header_t h)
{
/*
;; ->>HEADER<<- opcode: QUERY; status: NOERROR; id: 28028
;; Flags: qr rd ra; QUERY: 1; ANSWER: 1; AUTHORITY: 0; ADDITIONAL: 0
*/
	std::cout << "->>HEADER<<- opcode: " << h.Opcode << "; status: " << h.RCODE << "; id: " <<h.ID << std::endl;
	std::cout << "flags: qr " << h.QR << "AA: "<< h.AA << " TC " <<h.TC<<" RD "<<h.RD<<" RA " <<h.RA <<" Z " <<h.Z <<std::endl;
	std::cout << "QUER " <<h.QDCOUNT << " AN "<< h.ANCOUNT <<" NS " << h.NSCOUNT << " AR " << h.ARCOUNT << std::endl;
};

//TODO: reference for dOffset looks ugly 
size_t
append_label(char* domain, size_t& dOffset, size_t dSize, const uint8_t *buff, size_t bOffset, size_t bSize, bool couldBeCompressed=true)
{
	if ( bOffset >= bSize ) throw std::invalid_argument("label overflow");
	uint16_t lSize = buff[bOffset];
	bOffset++;
	if ( (lSize & 0xc0) == 0xc0 ) 
	{
		//compressed label
		return (lSize << 8) | buff[bOffset]; //TODO: looks like hack

	} else
	{
		if ( lSize == 0 ) return lSize;
		if ( (lSize & 0xc0) != 0 ) throw std::invalid_argument("unknown compression flag");
		
		std::memcpy(domain+dOffset, buff+bOffset, lSize);
		dOffset += lSize;
		domain[dOffset] = '.'; //FQDN YEAH
		dOffset++;
		domain[dOffset]=0;
		return lSize;
	}
}

size_t
parse_name(char* domain,size_t dSize, const uint8_t *buff, size_t bOffset, size_t bSize, bool couldBeCompressed=true)
{
	size_t dOffset = 0;
	domain[dOffset]=0;
	size_t nextFiledOffset = bOffset;
	size_t lSize;
	bool   compressed = false;
	while ( (lSize = append_label(domain, dOffset, dSize, buff, bOffset, bSize, couldBeCompressed)) != 0) 
	{
		if ( (lSize & 0xc000) == 0xc000 ) 
		{
			nextFiledOffset +=2;
			compressed = true;
			bOffset = lSize & 0x3fff;
		}
		else
		{
			if (!compressed) nextFiledOffset += lSize + 1;
			bOffset += lSize + 1;
		}
	}
	return nextFiledOffset + (compressed ? 0 : 1);
}

question_t
parse_question(const uint8_t * buff, size_t offset, size_t size, size_t &qOffset)
{	
	question_t ret;
	char domain[ MAX_NAME_LENGTH + 1];	
	size_t dOffset = 0;
	domain[dOffset]=0;

	dOffset = parse_name(domain, sizeof(domain), buff, offset, size); //TODO: make it dOffset, not buff offset

	std::memcpy(&ret.QTYPE, buff + dOffset, sizeof(ret.QTYPE));
	ret.QTYPE = ntohs(ret.QTYPE);
	dOffset += sizeof(ret.QTYPE);


	std::memcpy(&ret.QCLASS, buff + dOffset, sizeof(ret.QCLASS));
	ret.QCLASS = ntohs(ret.QCLASS);
	dOffset += sizeof(ret.QCLASS);

	ret.QNAME = domain;

	qOffset = dOffset - offset;
	return ret;
}

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
	resource_record_t ret;
	/*
	std::string NAME;
	uint16_t TYPE;
	uint16_t CLASS;
	uint32_t TTL;
	uint16_t RDLENGTH;
	void *RDATA;	
	*/
	char domain[ MAX_NAME_LENGTH + 1];	
	size_t dOffset = 0;
	domain[dOffset]=0;
	dOffset = parse_name(domain, sizeof(domain), buff, offset, size); //TODO: see parse_question

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
};

// https://www.cloudflare.com/learning/dns/dns-records/
// I guess, it's enough to implement commonly-used subset and print hex for other things...
const char* print_rdata(uint16_t,const void *,uint16_t) { return "";}

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

		header_t header = parse_header(raw_data.data(),raw_data.size());
		const size_t headerOffset = 6 * sizeof(int16_t);
		print_header(header);
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

	}
	catch (std::invalid_argument e)
	{
		std::cout << e.what();
		throw;
	}
	
    return 0;
}
