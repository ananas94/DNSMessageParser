#include "gtest/gtest.h"
#include "input.h"


class ValidInput :  public testing::TestWithParam<const char*> {

};

const char* testCases[] =
{
	"\"\\x6d\\x7c\\x81\\x80\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\x00\\x07\\x65\\x78\\x61\" \\",
 	"\"\\x6d\\x7c\\x81\\x80\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\x00\\x07\\x65\\x78\\x61\"",
 	"\n",
 	"\"\\x6d\\x7c\\x81\\x80\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\x00\\x07\\x65\\x78\\x61\" \\"
		"\n"
		"\"\\x6d\\x7c\\x81\\x80\""
};


INSTANTIATE_TEST_SUITE_P(Input,ValidInput,
		testing::ValuesIn(
				testCases
			));


TEST_P(ValidInput, SmokeTest)
{
	std::stringstream ss(GetParam());
	get_raw_data(ss);
}


class InvalidInput :  public testing::TestWithParam<const char*> {

};

const char* exceptionTestCases[] =
{
	"\"\\x6\"",  // 2 hex digits
	"\x6d",      // "" around
	"12",        // wtf?
 	"\"\\x6p\"",
};


INSTANTIATE_TEST_SUITE_P(Input,InvalidInput,
		testing::ValuesIn(
				exceptionTestCases
			));


TEST_P(InvalidInput, SmokeTest)
{
	std::stringstream ss(GetParam());
	EXPECT_THROW( get_raw_data(ss), std::invalid_argument );
}
