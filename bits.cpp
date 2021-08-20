#include <iostream>
#include <cstdint>

int main()
{
	uint16_t test = 0xFFFF;
	std::cout <<"16 " << (test>>16) << " 15 " << (test >> 15) <<std::endl;	
	return 0;
}
