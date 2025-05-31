// utils.cpp
#include "poolcommon/utils.h"

#include <string>      // for std::string
#include <cstdarg>     // for va_list, va_start, va_end, va_copy
#include <stdexcept>   // for std::runtime_error
#include <cstdint>     // for int64_t
#include <cstdlib>     // for nullptr

std::string vstrprintf(const char *format, va_list ap)
{
    // Start with a 50k stack buffer
    char stackBuf[50000];
    char *p = stackBuf;
    int limit = sizeof(stackBuf);
    int ret;

    for (;;)
    {
        va_list arg_ptr;
        va_copy(arg_ptr, ap);
#ifdef WIN32
        ret = _vsnprintf(p, limit, format, arg_ptr);
#else
        ret = vsnprintf(p, limit, format, arg_ptr);
#endif
        va_end(arg_ptr);

        if (ret < 0) {
            // vsnprintf error (invalid format or arguments)
            throw std::runtime_error("vstrprintf: formatting error (vsnprintf returned negative)");
        }

        if (ret < limit) {
            // Successfully formatted; ret is the number of characters written
            break;
        }

        // Buffer was too small; grow it and try again
        if (p != stackBuf) {
            delete[] p;
        }
        limit *= 2;
        p = new char[limit];
        if (p == nullptr) {
            throw std::bad_alloc();
        }
        // loop and retry
    }

    std::string result(p, p + ret);
    if (p != stackBuf) {
        delete[] p;
    }
    return result;
}

std::string real_strprintf(const std::string &format, int dummy, ...)
{
    va_list arg_ptr;
    va_start(arg_ptr, dummy);
    std::string str = vstrprintf(format.c_str(), arg_ptr);
    va_end(arg_ptr);
    return str;
}

std::string FormatMoney(int64_t n, int64_t rationalPartSize, bool fPlus)
{
    // This function formats n/rationalPartSize with proper decimal point.
    bool negative = (n < 0);
    if (negative) n = -n;

    int64_t integerPart = n / rationalPartSize;
    int64_t fractionalPart = n % rationalPartSize;

    // Build the integer part
    std::string s = std::to_string(integerPart);

    // Add decimal point and fractional part, padding with leading zeros
    if (fractionalPart > 0) {
        std::string frac = std::to_string(fractionalPart);
        // Pad leading zeros up to rationalPartSize's digit count
        int64_t temp = rationalPartSize;
        int digits = 0;
        while (temp > 1) {
            temp /= 10;
            digits++;
        }
        if ((int)frac.size() < digits) {
            frac = std::string(digits - frac.size(), '0') + frac;
        }
        s += "." + frac;
    }

    if (negative) {
        s = "-" + s;
    } else if (fPlus) {
        s = "+" + s;
    }
    return s;
}

bool parseMoneyValue(const char *value, const int64_t rationalPartSize, int64_t *out)
{
    // Parses a string like "123.45" into an int64_t = 123 * rationalPartSize + 45
    // Supports optional leading '-' or '+'.

    if (value == nullptr || out == nullptr) return false;

    const char *p = value;
    bool negative = false;
    if (*p == '-') {
        negative = true;
        p++;
    } else if (*p == '+') {
        p++;
    }

    int64_t integerPart = 0;
    while (*p && isdigit(*p)) {
        integerPart = integerPart * 10 + (*p - '0');
        p++;
    }

    int64_t fractionalPart = 0;
    int64_t fractionalMultiplier = rationalPartSize / 10;

    if (*p == '.') {
        p++;
        while (*p && isdigit(*p) && fractionalMultiplier > 0) {
            fractionalPart += (int64_t)(*p - '0') * fractionalMultiplier;
            fractionalMultiplier /= 10;
            p++;
        }
        // Skip any extra digits
        while (*p && isdigit(*p)) {
            p++;
        }
    }

    if (*p != '\0') {
        // Unexpected character
        return false;
    }

    int64_t result = integerPart * rationalPartSize + fractionalPart;
    if (negative) result = -result;
    *out = result;
    return true;
}
