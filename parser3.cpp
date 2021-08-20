#include <iostream>
#include <string>

int main ()
{
	while (std::cin.good()) {
		std::string str;
		std::cin >> str;
		std::cout << str << std::endl;
		getline(std::cin,str);
		std::cout << str << std::endl;
	}
}
