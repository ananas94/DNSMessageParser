#include <memory>
#include <iostream>
#include <vector>
#include <sstream>
#include <string>
#include <cstdint>

class RData;

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

class RData
{
	protected:
		const void* data;
		const size_t size;
	public:
		RData(const void* d, size_t s): data(d), size(s) {};
		virtual operator std::string()
		{
			std::stringstream ss;
			ss << "unknown rdata(" << this->size <<") hex: [";
			ss.setf(std::ios_base::hex, std::ios_base::basefield);
			ss.setf(std::ios_base::showbase);
			for (size_t i=0; i< size; i++)
				ss << (int) ((const uint8_t*)data)[i] << " ";

			ss.unsetf(std::ios_base::hex);
			ss<< "]";

			return ss.str();
		}
};



struct resource_record_t{
	std::string NAME;
	uint16_t TYPE;
	uint16_t CLASS;
	uint32_t TTL;
	//TODO: memory safety unique_ptr and vector?? destructor?
	std::unique_ptr<RData> RDATA;
};

struct dns_message_t{
	header_t Header;
	std::vector<question_t> Question;
	std::vector<resource_record_t> Answer;
	/*std::vector<resource_record_t> Authority;
	std::vector<resource_record_t> Additional;*/
};	


dns_message_t
get_message()
{
	dns_message_t ret;
	return std::move(ret);
}

int main()
{
	dns_message_t m = get_message()  ;
	std::cout <<m.Header.ID << std::endl;
	return 0;
}
