
#include <phnt_windows.h>
#include <phnt.h>
#include <string>

// Get the security catalog that will be patched
bool GetCatalog(LPCWSTR lpResourceName, PVOID pBuf, SIZE_T maxLength, DWORD& bytesWritten);
