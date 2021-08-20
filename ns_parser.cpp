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


struct header_t{
	uint16_t ID;
	uint16_t QR:1,Opcode:4,AA:1,TC:1,RD:1,RA:1,Z:1,RCODE:4;
	uint16_t QDCOUNT;
	uint16_t ANCOUNT;
	uint16_t NSCOUNT;
	uint16_t ARCOUNT;
};

struct question_t{
	char *QNAME;
	uint16_t QTYPE;
	uint16_t QCLASS;
};

struct resource_record_t{
	char *NAME;
	uint16_t TYPE;
	uint16_t CLASS;
	uint32_t TTL;
	uint16_t RDLENGTH;
	void *RDATA;	
};

struct dns_message{
	header_t Header;
	question_t *Question;
	resource_record_t *Answer;
	resource_record_t *Authority;
	resource_record_t *Additional;
};	


int8_t char_to_4bit(char c)
{
	if (c >= '0' && c<='9')
		return c - '0';
	else if (c >='a' && c<='f')
		return c - 'a'+10;
	else if (c >='A' && c<='F')
		return c - 'A'+10;
	else
	{
		std::string errMsg;
		errMsg += c;
		errMsg += " not a hex";
		throw std::invalid_argument(errMsg);
		//throw std::invalid_argument(std::format("{} is not hex",c));
	}
}

std::vector<uint8_t> hex_to_raw(const std::string &in)
{
	size_t in_size = in.size();
	if ( in_size % 4 != 0 ) throw std::invalid_argument("not a hex");
		//throw std::invalid_argument( std::format("{} is not hex string", in));
	std::vector<uint8_t> ret( in_size / 4 );
	for (size_t i=0; i < in_size; i+=4)
	{
		uint8_t b = (char_to_4bit( in[i +2]) << 4) + char_to_4bit( in[i+3]);
		ret[i / 4] = b;
	}
	return ret;
}

int main() {
    /* Enter your code here. Read input from STDIN. Print output to STDOUT */
	std::string input;
	std::cin >> input;
	try{
		auto raw_data = hex_to_raw(input);
		for (auto c : raw_data)
			std::cout <<(int)c<< " ";
		std::cout<<std::endl;
	}
	catch (std::invalid_argument e)
	{
		std::cout << e.what();
		throw;
	}
	
    return 0;
}
