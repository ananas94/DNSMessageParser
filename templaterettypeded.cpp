#include <iostream>
#include <cstdint>
#include <cstring>


uint8_t raw_data[32] = {1,2,3,4,5,6,7,8};
 
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



template<typename T>
T
Get()
{
	T ret;
	std::memcpy(&ret, raw_data, sizeof(ret));
	ret= ntoh(ret);
	return ret;
}

int main()
{
	uint16_t i16 = Get<uint16_t>();
	uint16_t i32 = Get<uint32_t>();
	std::cout << i16 << " " << i32 << std::endl;
	return 0;
}



