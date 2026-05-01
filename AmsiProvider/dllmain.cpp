#include "provider.h"

#include <windows.h>
#include <strsafe.h>
#include <new>

// Force-export COM entry points for regsvr32.
#pragma comment(linker, "/EXPORT:DllCanUnloadNow,PRIVATE")
#pragma comment(linker, "/EXPORT:DllGetClassObject,PRIVATE")
#pragma comment(linker, "/EXPORT:DllRegisterServer,PRIVATE")
#pragma comment(linker, "/EXPORT:DllUnregisterServer,PRIVATE")

// =====================================================
// DLL Main + COM Registration for Mini EDR AMSI Provider
// Role:
// 1. Export COM functions required by regsvr32
// 2. Register CLSID under HKLM\SOFTWARE\Classes\CLSID
// 3. Register provider under HKLM\SOFTWARE\Microsoft\AMSI\Providers
// 4. Clean registry keys during unregister
// =====================================================

long g_cRefModule = 0;
HMODULE g_hModule = NULL;

static const char* CLSID_STRING = "{11111111-2222-3333-4444-555555555555}";
static const char* PROVIDER_NAME = "Mini EDR AMSI Provider";
static const char* PROG_ID = "MiniEDR.AmsiProvider";

// ================= REGISTRY HELPERS =================
static HRESULT SetRegistryStringA(HKEY root, const char* subKey, const char* valueName, const char* data)
{
    HKEY hKey = NULL;

    LSTATUS status = RegCreateKeyExA(
        root,
        subKey,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        NULL,
        &hKey,
        NULL);

    if (status != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(status);

    status = RegSetValueExA(
        hKey,
        valueName,
        0,
        REG_SZ,
        reinterpret_cast<const BYTE*>(data),
        static_cast<DWORD>(strlen(data) + 1));

    RegCloseKey(hKey);

    if (status != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(status);

    return S_OK;
}

static HRESULT DeleteRegistryTreeA(HKEY root, const char* subKey)
{
    LSTATUS status = RegDeleteTreeA(root, subKey);

    if (status == ERROR_FILE_NOT_FOUND)
        return S_OK;

    if (status != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(status);

    return S_OK;
}

// ================= CLASS FACTORY =================
class CClassFactory : public IClassFactory
{
private:
    volatile ULONG m_refCount;

public:
    CClassFactory() : m_refCount(1)
    {
        InterlockedIncrement(&g_cRefModule);
    }

    ~CClassFactory()
    {
        InterlockedDecrement(&g_cRefModule);
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv)
            return E_POINTER;

        if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IClassFactory))
        {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }

        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override
    {
        return InterlockedIncrement(&m_refCount);
    }

    ULONG STDMETHODCALLTYPE Release() override
    {
        ULONG count = InterlockedDecrement(&m_refCount);

        if (count == 0)
            delete this;

        return count;
    }

    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv) override
    {
        if (!ppv)
            return E_POINTER;

        *ppv = nullptr;

        if (pUnkOuter != nullptr)
            return CLASS_E_NOAGGREGATION;

        CAmsiProvider* pAmsiProvider = new (std::nothrow) CAmsiProvider();
        if (!pAmsiProvider)
            return E_OUTOFMEMORY;

        HRESULT hr = pAmsiProvider->QueryInterface(riid, ppv);
        pAmsiProvider->Release();

        return hr;
    }

    HRESULT STDMETHODCALLTYPE LockServer(BOOL fLock) override
    {
        if (fLock)
            InterlockedIncrement(&g_cRefModule);
        else
            InterlockedDecrement(&g_cRefModule);

        return S_OK;
    }
};

// ================= COM EXPORTS =================
STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv)
{
    if (!ppv)
        return E_POINTER;

    *ppv = nullptr;

    if (!IsEqualCLSID(rclsid, CLSID_CustomAmsiProvider))
        return CLASS_E_CLASSNOTAVAILABLE;

    CClassFactory* pFactory = new (std::nothrow) CClassFactory();
    if (!pFactory)
        return E_OUTOFMEMORY;

    HRESULT hr = pFactory->QueryInterface(riid, ppv);
    pFactory->Release();

    return hr;
}

STDAPI DllCanUnloadNow()
{
    return (g_cRefModule == 0) ? S_OK : S_FALSE;
}

STDAPI DllRegisterServer()
{
    if (!g_hModule)
        return E_FAIL;

    char modulePath[MAX_PATH] = { 0 };

    DWORD len = GetModuleFileNameA(g_hModule, modulePath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH)
        return HRESULT_FROM_WIN32(GetLastError());

    HRESULT hr = S_OK;

    char clsidKey[512] = { 0 };
    char inprocKey[512] = { 0 };
    char progIdKey[512] = { 0 };
    char amsiProviderKey[512] = { 0 };

    StringCchPrintfA(clsidKey, ARRAYSIZE(clsidKey), "SOFTWARE\\Classes\\CLSID\\%s", CLSID_STRING);
    StringCchPrintfA(inprocKey, ARRAYSIZE(inprocKey), "SOFTWARE\\Classes\\CLSID\\%s\\InprocServer32", CLSID_STRING);
    StringCchPrintfA(progIdKey, ARRAYSIZE(progIdKey), "SOFTWARE\\Classes\\%s\\CLSID", PROG_ID);
    StringCchPrintfA(amsiProviderKey, ARRAYSIZE(amsiProviderKey), "SOFTWARE\\Microsoft\\AMSI\\Providers\\%s", CLSID_STRING);

    // 1. COM CLSID display name
    hr = SetRegistryStringA(HKEY_LOCAL_MACHINE, clsidKey, NULL, PROVIDER_NAME);
    if (FAILED(hr))
        return hr;

    // 2. InprocServer32 DLL path
    hr = SetRegistryStringA(HKEY_LOCAL_MACHINE, inprocKey, NULL, modulePath);
    if (FAILED(hr))
        return hr;

    // 3. Threading model
    hr = SetRegistryStringA(HKEY_LOCAL_MACHINE, inprocKey, "ThreadingModel", "Both");
    if (FAILED(hr))
        return hr;

    // 4. Optional ProgID mapping
    hr = SetRegistryStringA(HKEY_LOCAL_MACHINE, progIdKey, NULL, CLSID_STRING);
    if (FAILED(hr))
        return hr;

    // 5. AMSI Provider registration
    hr = SetRegistryStringA(HKEY_LOCAL_MACHINE, amsiProviderKey, NULL, PROVIDER_NAME);
    if (FAILED(hr))
        return hr;

    return S_OK;
}

STDAPI DllUnregisterServer()
{
    HRESULT hr1 = S_OK;
    HRESULT hr2 = S_OK;
    HRESULT hr3 = S_OK;

    char clsidKey[512] = { 0 };
    char progIdRoot[512] = { 0 };
    char amsiProviderKey[512] = { 0 };

    StringCchPrintfA(clsidKey, ARRAYSIZE(clsidKey), "SOFTWARE\\Classes\\CLSID\\%s", CLSID_STRING);
    StringCchPrintfA(progIdRoot, ARRAYSIZE(progIdRoot), "SOFTWARE\\Classes\\%s", PROG_ID);
    StringCchPrintfA(amsiProviderKey, ARRAYSIZE(amsiProviderKey), "SOFTWARE\\Microsoft\\AMSI\\Providers\\%s", CLSID_STRING);

    hr1 = DeleteRegistryTreeA(HKEY_LOCAL_MACHINE, amsiProviderKey);
    hr2 = DeleteRegistryTreeA(HKEY_LOCAL_MACHINE, clsidKey);
    hr3 = DeleteRegistryTreeA(HKEY_LOCAL_MACHINE, progIdRoot);

    if (FAILED(hr1)) return hr1;
    if (FAILED(hr2)) return hr2;
    if (FAILED(hr3)) return hr3;

    return S_OK;
}

// ================= DLL MAIN =================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    UNREFERENCED_PARAMETER(reserved);

    if (reason == DLL_PROCESS_ATTACH)
    {
        g_hModule = hModule;
        DisableThreadLibraryCalls(hModule);
    }

    return TRUE;
}
