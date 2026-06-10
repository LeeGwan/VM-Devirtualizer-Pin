#include "PIN_CLASS/PIN_CLASS.h"


int main(int argc, char* argv[])
{

    PIN_CLASS g_bPIN_CLASS;
    if (!g_bPIN_CLASS.pinClassInit(argc, argv))
    {
        return -1;
    }
    g_bPIN_CLASS.pinClassStart();
    return 0;

}
