#ifndef VOMS_ASN1_UTILS_H
#define VOMS_ASN1_UTILS_H

#include <openssl/asn1.h>
#include <iomanip>
#include <sstream>
#include <string>

namespace voms_internal {

// generate a string preferably in local time, with TZ indication
inline std::string asn1_time_to_string(ASN1_TIME const* time)
{
  tm tm_utc;
  ASN1_TIME_to_tm(time, &tm_utc);
  std::ostringstream os;
#ifdef HAVE_TIMEGM
  time_t t_utc = timegm(&tm_utc);
  tm* tm_ptr = localtime(&t_utc);
  os << std::put_time(tm_ptr, "%c %Z");
#else
  os << std::put_time(&tm_utc, "%c GMT");
#endif
  return os.str();
}

inline std::string to_string(ASN1_STRING const* value)
{
  if (value == nullptr) {
    return {};
  }

  return std::string{
    reinterpret_cast<char const*>(ASN1_STRING_get0_data(value)),
    static_cast<std::string::size_type>(ASN1_STRING_length(value))
  };
}

} // namespace voms_internal

#endif
