#ifndef DSN_CONSTANTS
#define DSN_CONSTANTS

#include <unordered_map>
const size_t UDP_SIZE_LIMIT = 512;
const size_t MAX_NAME_LENGTH = 255;

// All maps could be replaced by std::array
const std::unordered_map<uint16_t, std::string> types = {
    {1, "A"},       {2, "NS"},      {3, "MD"},   {4, "MF"},
    {5, "CNAME"},   {6, "SOA"},     {7, "MB"},   {8, "MG"},
    {9, "MR"},      {10, "NULL"},   {11, "WKS"}, {12, "PTR"},
    {13, "HINFO"},  {14, "MINFO"},  {15, "MX"},  {16, "TXT"},

    {28, "AAAA"},   {33, "SRV"},

    {252, "AXFR"}, // QTYPES
    {253, "MAILB"}, {254, "MAILA"}, {255, "*"}};

const std::unordered_map<uint16_t, std::string> classes = {
    {1, "IN"}, {2, "CS"}, {3, "CH"}, {4, "HS"}, {255, "*"}, // QCLASS
};

const std::unordered_map<uint16_t, std::string> opcodes = {
    {0, "QUERY"}, {1, "IQUERY"}, {2, "STATUS"}};

const std::unordered_map<uint16_t, std::string> statuses = {
    {0, "NOERROR"},   {1, "FORMATERROR"},    {2, "SERVERFAILURE"},
    {3, "NAMEERROR"}, {4, "NOTIMPLEMENTED"}, {5, "REFUSED"},

};

#endif
