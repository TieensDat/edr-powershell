#pragma once

#include <windows.h>
#include <amsi.h>
#include <unknwn.h>

// {11111111-2222-3333-4444-555555555555}
static const CLSID CLSID_CustomAmsiProvider =
{ 0x11111111,0x2222,0x3333,{0x44,0x44,0x55,0x55,0x55,0x55,0x55,0x55} };

class CAmsiProvider : public IAntimalwareProvider
{
private:
    volatile ULONG m_refCount;

public:

    CAmsiProvider() : m_refCount(1) {}
    virtual ~CAmsiProvider() {}

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv);
    ULONG STDMETHODCALLTYPE AddRef();
    ULONG STDMETHODCALLTYPE Release();

    // AMSI
    IFACEMETHODIMP Scan(IAmsiStream* stream, AMSI_RESULT* result);
    IFACEMETHODIMP_(void) CloseSession(ULONGLONG session);
    IFACEMETHODIMP DisplayName(LPWSTR* displayName);
};