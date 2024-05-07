#include <windows.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpCmdLine, int nCmdShow) {
    MessageBoxW(NULL, L"Este es tu mensaje", L"Título del Mensaje", MB_OK);
    return 0;
}
