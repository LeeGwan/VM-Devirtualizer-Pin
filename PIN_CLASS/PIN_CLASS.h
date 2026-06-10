//------------------------------------------------------------------
//              
//  FILE:       PIN_CLASS.h
//  AUTHOR:     PinTool Developer
//  PROJECT:    VMAnalyzer
//  COMPONENT:  -
//  DATE:       2026-06-10
//  COMMENTS:   -
//              
//------------------------------------------------------------------

#pragma once
#include "pin.H"
#include <stdint.h>

#pragma pack(push, 1)
/**
    @brief      Structure representing the virtual machine context (registers and state).
    @date       2026-02-13
    @author     PinTool Developer
*/
typedef struct _VMCONTEXT
{
    uint32_t VM_EBP;                ///< +0x00: Virtual EBP register
    uint32_t VM_EDI;                ///< +0x04: Virtual EDI register
    uint32_t VM_EBX;                ///< +0x08: Virtual EBX register
    uint32_t VM_EAX;                ///< +0x0C: Virtual EAX register
    uint32_t VM_ESI;                ///< +0x10: Virtual ESI register
    uint32_t VM_EDX;                ///< +0x14: Virtual EDX register
    uint32_t VM_ECX;                ///< +0x18: Virtual ECX register
    uint32_t VM_EFLAGS;             ///< +0x1C: Virtual EFLAGS register
    uint32_t unk_20;                ///< +0x20: Unknown field
    uint32_t unk_24;                ///< +0x24: Unknown field
    uint32_t unk_28;                ///< +0x28: Unknown field
    uint32_t unk_2C;                ///< +0x2C: Unknown field
    uint32_t init_flag;             ///< +0x30: Control Code lock cmpxchg target
    uint32_t unk_34;                ///< +0x34: Unknown field
    ADDRINT* handler_table[0x96];   ///< +0x38: Array of 0x96 virtual handler addresses
} VMCONTEXT, * LPVMCONTEXT;
#pragma pack(pop)

class PIN_CLASS
{
    ////////////////////////////////////////////////////////////
    ///////////////////// Public Methods ///////////////////////
    ////////////////////////////////////////////////////////////
public:
    PIN_CLASS();
    ~PIN_CLASS();
    bool pinClassInit(int argc, char* argv[]);
    void pinClassStart();

    ////////////////////////////////////////////////////////////
    ///////////////////// Private Callbacks ////////////////////
    ////////////////////////////////////////////////////////////
private:
    static VOID IMG_Callbackfunc(IMG img, VOID* v);
    static VOID INS_Callbackfunc(INS ins, VOID* v);
    static VOID Fini_Callbackfunc(INT32 code, VOID* v);

    ////////////////////////////////////////////////////////////
    ///////////////////// State Control ////////////////////////
    ////////////////////////////////////////////////////////////
    static VOID TurnOnVmSwitch();
    static VOID TurnOffVmSwitch();
    static BOOL CheckIfVmActive();

    ////////////////////////////////////////////////////////////
    ///////////////////// Analysis Routines ////////////////////
    ////////////////////////////////////////////////////////////
    static VOID OnHandlerEnter(ADDRINT opcode, ADDRINT target);
    static VOID OnLea(ADDRINT ea, ADDRINT esp, BOOL isStack);
    static VOID OnMemRead(ADDRINT addr, UINT32 size, ADDRINT esp, BOOL isStack);
    static VOID OnMemWriteBefore(ADDRINT addr, UINT32 size, ADDRINT esp);
    static VOID OnMemWriteAfter(BOOL isStack);
    static VOID DumpHandlerSummary();

    ////////////////////////////////////////////////////////////
    ///////////////////// Instrumentation //////////////////////
    ////////////////////////////////////////////////////////////
    void ProcessImage(const IMG& img);
    void AnalyzeInstruction(const INS& ins);
};