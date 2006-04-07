
#include <string>
#include "fqan.h"

class Contact
{

public:

  Contact(const std::string& s)
  {
    /* separate nick from fqan */
    std::string::size_type pos = s.find(':');
    if (pos != std::string::npos)
    {
      vo_ = s.substr(0, pos);
      fqan_ = s.substr(pos+1);  
    }
    else
    {
      vo_ = s;
      fqan_ = "/" + s;
    }
  }
  
  std::string vo() const
  {
    return vo_;
  }
  
  std::string fqan() const
  {
    return fqan_;
  }

private:

  std::string vo_;
  std::string fqan_;

};
