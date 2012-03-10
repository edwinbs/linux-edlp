#pragma once

#include <string>

#ifdef __cplusplus
extern "C" {

class CDLPEngineProto
{
public:
    CDLPEngineProto();
    
    bool    OnOpen(const std::string& sFileName, bool bWrite = false);
    
private:
    bool    IsExternal(const std::string& sFileName);

    bool    m_bDirty;
};

}
#endif

