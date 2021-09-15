#include <fstream>
#include "gtest/gtest.h"
#include "input.h"
#include "MessageParser.h"
#include <vector>
#include <iostream>


class ParsingTest :  public testing::TestWithParam<const char*> {

};

const char* inputFiles[] =
{
	"input", "inputQAA", "inputQAAAA", "inputQAAAd", "inputQAuthAdd", "inputQSRV"
};


INSTANTIATE_TEST_SUITE_P(Input,ParsingTest,
		testing::ValuesIn(
				inputFiles
			));


TEST_P(ParsingTest, SmokeTest)
{
	std::string path = "inputs/";
	path += GetParam();
	std::ifstream istrm(path,std::ifstream::in);
	std::vector<uint8_t> input = get_raw_data(istrm);
	size_t inputSize = input.size();
	for (size_t i =0; i<inputSize; i++)
	{
		std::vector<uint8_t> vecCopy(input);
		for (size_t j = 0; j < i; j++)
			vecCopy.pop_back();
		MessageParser mp(std::move(vecCopy));
		if (i==0)
		{
			EXPECT_NO_THROW({dns_message_t dm = mp.GetDnsMessage();});
		}
		else
		{
			EXPECT_THROW({dns_message_t dm = mp.GetDnsMessage();},std::invalid_argument);
		}
	}
}


