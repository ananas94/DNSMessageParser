#include <cstdio>
#include <cstdint>
#include <iostream>

int main()
{
	int var;
	scanf("\\x%2x", &var);
	std::cout << var <<std::endl;
	return 0;
}
