//------------------------------------------------------------------
//              
//  FILE:       PIN_CLASS.cpp
//  AUTHOR:     PinTool Developer
//  PROJECT:    VMAnalyzer
//  COMPONENT:  -
//  DATE:       2026-06-10
//  COMMENTS:   -
//              
//------------------------------------------------------------------

#include "PIN_CLASS.h"
#include <iostream>
#include <map>

////////////////////////////////////////////////////////////
///////////////////// Global Variable //////////////////////
////////////////////////////////////////////////////////////

bool       g_vmActive = false;          ///< VM activation flag
ADDRINT    g_vmStart = 0;               ///< VM section start address
ADDRINT    g_vmEnd = 0;                 ///< VM section end address
ADDRINT    g_vmContextAddr = 0;         ///< Context address
VMCONTEXT* g_vmContext = nullptr;       ///< Safe heap memory pointer for context

ADDRINT    g_curHandler = 0;            ///< Current handler address
ADDRINT    g_curOpcode = 0;             ///< Current opcode
UINT32     g_step = 0;                  ///< Step counter

// Write value tracking (store BEFORE -> read AFTER)
ADDRINT    g_wAddr = 0;                 ///< Write address tracking
UINT32     g_wSize = 0;                 ///< Write size tracking
ADDRINT    g_wEsp = 0;                  ///< Write ESP tracking

bool       g_inDispatch = false;        ///< Noise suppression flag for dispatcher (next handler address decoding)

/**
    @brief      Cumulative statistics by handler type
    @date       2026-02-13
    @author     PinTool Developer
*/
struct HandlerInfo
{
    UINT32      callCount = 0;          ///< Handler call count
    UINT32      readCount = 0;          ///< Memory read count
    UINT32      writeCount = 0;         ///< Memory write count
    std::string sampleOpcode;           ///< Sample opcode string
};
std::map<ADDRINT, HandlerInfo> g_handlerStats; ///< Map for handler statistics

static const std::string kVmSection = ".v-lizer"; ///< Target VM section name
static const ADDRINT     kVmContextPtrOffset = 0x8a3; ///< Offset for context pointer

// Signature constants for dispatcher decoding routine (writing this to STACK starts dispatcher)
static const ADDRINT     kDispatchMagic1 = 0x4b82; ///< Dispatcher signature 1
static const ADDRINT     kDispatchMagic2 = 0x25c5; ///< Dispatcher signature 2

////////////////////////////////////////////////////////////
///////////////////// Region Classification ////////////////
////////////////////////////////////////////////////////////

/**
    @brief      Returns the name of the memory region pointed to by x. \n
                Classifies whether it's a field or category.
    @date       2026-02-13
    @author     PinTool Developer
    @param      x       Address or value to classify
    @param      esp     Current ESP (for stack identification)
    @param      isStack Flag indicating if it is a stack operation
    @return     VMCONTEXT field name / "STACK" / "VLIZER" / "" (Unclassified)
*/
static std::string RegionName(ADDRINT x, ADDRINT esp, BOOL isStack)
{
    if (g_vmContextAddr && x >= g_vmContextAddr &&
        x < g_vmContextAddr + sizeof(VMCONTEXT))
    {
        UINT32 off = (UINT32)(x - g_vmContextAddr);
        switch (off) {
        case 0x00: return "VM_EBP";  case 0x04: return "VM_EDI";
        case 0x08: return "VM_EBX";  case 0x0C: return "VM_EAX";
        case 0x10: return "VM_ESI";  case 0x14: return "VM_EDX";
        case 0x18: return "VM_ECX";  case 0x1C: return "VM_EFLAGS";
        case 0x30: return "init_flag";
        default:
            if (off >= 0x38) return "handler_table";
            return "VMCTX+" + StringFromAddrint(off);
        }
    }

    if (isStack) return "STACK";
    if (g_vmStart && x >= g_vmStart && x < g_vmEnd) return "Read OPCODE";
    return "";
}

/**
    @brief      Labels the address in the format "[Region]0xADDR". \n
                If region identification fails, it returns [MEM].
    @date       2026-02-13
    @author     PinTool Developer
    @param      addr    Target address
    @param      esp     Current ESP
    @param      isStack Flag indicating if it is a stack operation
    @return     e.g., "[STACK]0x0019fe08", "[VM_EAX]0x...", "[MEM]0x..."
*/
static std::string Loc(ADDRINT addr, ADDRINT esp, BOOL isStack)
{
    std::string r = RegionName(addr, esp, isStack);
    if (r.empty()) r = "MEM";          ///< Other (Heap/Target data, etc.)
    return "[" + r + "]" + StringFromAddrint(addr);
}

/**
    @brief      Returns a label indicating which region the value points to.
    @date       2026-02-13
    @author     PinTool Developer
    @param      val     Value to check
    @param      esp     Current ESP
    @param      isStack Flag indicating if it is a stack operation
    @return     e.g., " (->STACK)" / " (->VLIZER)" / "" (No region pointed to)
*/
static std::string ValTag(ADDRINT val, ADDRINT esp, BOOL isStack)
{
    std::string r = RegionName(val, esp, isStack);
    return r.empty() ? "" : " (->" + r + ")";
}

////////////////////////////////////////////////////////////
///////////////////// Initialization ///////////////////////
////////////////////////////////////////////////////////////

PIN_CLASS::PIN_CLASS() { PIN_InitSymbols(); }
PIN_CLASS::~PIN_CLASS() {}

bool PIN_CLASS::pinClassInit(int argc, char* argv[])
{
    if (PIN_Init(argc, argv) != FALSE) { std::cout << "[PIN] Init failed\n"; return false; }
    std::cout << "[PIN] Init success\n";
    return true;
}

void PIN_CLASS::pinClassStart()
{
    IMG_AddInstrumentFunction(IMG_Callbackfunc, this);
    INS_AddInstrumentFunction(INS_Callbackfunc, this);
    PIN_AddFiniFunction(Fini_Callbackfunc, this);
    PIN_StartProgram();
}

////////////////////////////////////////////////////////////
///////////////////// Callbacks ////////////////////////////
////////////////////////////////////////////////////////////

VOID PIN_CLASS::IMG_Callbackfunc(IMG img, VOID* v)
{
    if (!IMG_IsMainExecutable(img)) return;
    static_cast<PIN_CLASS*>(v)->ProcessImage(img);
}

VOID PIN_CLASS::INS_Callbackfunc(INS ins, VOID* v)
{
    ADDRINT ip = INS_Address(ins);
    if (!g_vmStart || !g_vmEnd || ip < g_vmStart || ip > g_vmEnd) return;
    static_cast<PIN_CLASS*>(v)->AnalyzeInstruction(ins);
}

VOID PIN_CLASS::Fini_Callbackfunc(INT32 code, VOID* v)
{
    DumpHandlerSummary();
    std::cout << "\n[PIN] target exited (code " << code << ")\n";
}

void PIN_CLASS::ProcessImage(const IMG& img)
{
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
        if (SEC_Name(sec) == kVmSection)
        {
            g_vmStart = SEC_Address(sec);
            g_vmEnd = g_vmStart + SEC_Size(sec);
            std::cout << "[PIN] " << kVmSection << " @ " << StringFromAddrint(g_vmStart) << "\n";
            break;
        }
}

////////////////////////////////////////////////////////////
///////////////////// State Control ////////////////////////
////////////////////////////////////////////////////////////

VOID PIN_CLASS::TurnOnVmSwitch()
{
    g_vmActive = true;
    PIN_SafeCopy(&g_vmContextAddr, (VOID*)(g_vmStart + kVmContextPtrOffset), sizeof(g_vmContextAddr));
    g_vmContext = reinterpret_cast<VMCONTEXT*>(g_vmContextAddr);
}
VOID PIN_CLASS::TurnOffVmSwitch() { g_vmActive = false; }
BOOL PIN_CLASS::CheckIfVmActive() { return g_vmActive ? TRUE : FALSE; }

////////////////////////////////////////////////////////////
///////////////////// Analysis Routines ////////////////////
////////////////////////////////////////////////////////////

/**
    @brief      Called immediately after dispatcher jmp. \n
                Records handler entry and disables dispatch noise.
    @date       2026-02-13
    @author     PinTool Developer
    @param      opcode  Entry handler opcode (eax)
    @param      target  Actual jumped handler address
*/
VOID PIN_CLASS::OnHandlerEnter(ADDRINT opcode, ADDRINT target)
{
    g_curHandler = target;
    g_curOpcode = opcode;
    g_inDispatch = false;   ///< Disable noise suppression as handler body starts

    HandlerInfo& h = g_handlerStats[target];
    h.callCount++;
    if (h.sampleOpcode.empty()) h.sampleOpcode = StringFromAddrint(opcode);

    LOG("[" + StringFromAddrint(g_step++) + "] op(DECODING)=" + StringFromAddrint(opcode) +
        " handler=" + StringFromAddrint(target) + "\n");
}

/**
    @brief      Called upon lea execution. \n
                Logs only the "calculated address" without reading memory.
    @date       2026-02-13
    @author     PinTool Developer
    @param      ea      Effective address calculated by lea (IARG_EXPLICIT_MEMORY_EA)
    @param      esp     Current ESP
    @param      isStack Flag indicating if it is a stack operation
    @remarks    Since lea does not access memory but calculates an address, it is labeled as [LEA] to distinguish from READ.
*/
VOID PIN_CLASS::OnLea(ADDRINT ea, ADDRINT esp, BOOL isStack)
{
    if (!g_curHandler || g_inDispatch) return;
    LOG("      LEA   -> " + Loc(ea, esp, isStack) + "\n");   ///< ea = calculated address (does not read value)
}

/**
    @brief      Called upon memory read. \n
                Logs classified region for both address and value. Suppresses dispatch section.
    @date       2026-02-13
    @author     PinTool Developer
    @param      addr    Memory read address
    @param      size    Size of memory read
    @param      esp     Current ESP
    @param      isStack Flag indicating if it is a stack operation
*/
VOID PIN_CLASS::OnMemRead(ADDRINT addr, UINT32 size, ADDRINT esp, BOOL isStack)
{
    if (!g_curHandler) return;
    g_handlerStats[g_curHandler].readCount++;
    if (g_inDispatch) return;   ///< Skip dispatcher decoding noise

    ADDRINT val = 0;
    PIN_SafeCopy(&val, (VOID*)addr, (size < sizeof(ADDRINT)) ? size : sizeof(ADDRINT));

    LOG("      READ  " + Loc(addr, esp, isStack) +
        " val:" + StringFromAddrint(val) + ValTag(val, esp, isStack) + "\n");
}

/**
    @brief      BEFORE memory write. \n
                Stores address, size, and esp (Value is checked in AFTER).
    @date       2026-02-13
    @author     PinTool Developer
    @param      addr    Memory write address
    @param      size    Size of memory write
    @param      esp     Current ESP
*/
VOID PIN_CLASS::OnMemWriteBefore(ADDRINT addr, UINT32 size, ADDRINT esp)
{
    g_wAddr = addr; g_wSize = size; g_wEsp = esp;
}

/**
    @brief      AFTER memory write. \n
                Logs classified address and value if not in a dispatch section.
    @date       2026-02-13
    @author     PinTool Developer
    @param      isStack Flag indicating if it is a stack operation
*/
VOID PIN_CLASS::OnMemWriteAfter(BOOL isStack)
{
    if (!g_curHandler) return;
    g_handlerStats[g_curHandler].writeCount++;

    ADDRINT val = 0;
    PIN_SafeCopy(&val, (VOID*)g_wAddr, (g_wSize < sizeof(ADDRINT)) ? g_wSize : sizeof(ADDRINT));

    // If the written value is the dispatcher decoding signature, treat subsequent operations as noise until the next handler entry
    if (val == kDispatchMagic1 || val == kDispatchMagic2)
        g_inDispatch = true;

    if (g_inDispatch) return;   ///< Skip dispatcher noise

    LOG("      WRITE " + Loc(g_wAddr, g_wEsp, isStack) +
        " <- " + StringFromAddrint(val) + ValTag(val, g_wEsp, isStack) + "\n");
}

/**
    @brief      Outputs a grouped summary by handler upon termination.
    @date       2026-02-13
    @author     PinTool Developer
*/
VOID PIN_CLASS::DumpHandlerSummary()
{
    LOG("\n================= HANDLER SUMMARY =================\n");
    LOG("handler        callscount       readscount     writescount    opcode(Decoding)\n");
    for (auto& kv : g_handlerStats)
    {
        const HandlerInfo& h = kv.second;
        LOG(StringFromAddrint(kv.first) + "   " +
            StringFromAddrint(h.callCount) + "    " +
            StringFromAddrint(h.readCount) + "    " +
            StringFromAddrint(h.writeCount) + "    " + h.sampleOpcode + "\n");
    }
    LOG("==================================================\n");
}

////////////////////////////////////////////////////////////
///////////////////// Instruction Instrumentation //////////
////////////////////////////////////////////////////////////

void PIN_CLASS::AnalyzeInstruction(const INS& ins)
{
    OPCODE op = INS_Opcode(ins);

    if (op == XED_ICLASS_PUSHAD)
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)TurnOnVmSwitch, IARG_END);
    else if (op == XED_ICLASS_POPAD)
    {
        INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)CheckIfVmActive, IARG_END);
        INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)TurnOffVmSwitch, IARG_END);
    }

    if (CheckIfVmActive())
    {
        // 1. Dispatcher jmp [edi+eax*4] - Handler entry
        if (INS_IsIndirectControlFlow(ins) && !INS_IsRet(ins) &&
            INS_IsValidForIpointTakenBranch(ins) &&
            INS_MemoryBaseReg(ins) == REG_EDI &&
            INS_MemoryIndexReg(ins) == REG_EAX &&
            INS_MemoryScale(ins) == 4)
        {
            INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)OnHandlerEnter,
                IARG_REG_VALUE, REG_EAX,
                IARG_BRANCH_TARGET_ADDR,
                IARG_END);
        }

        // 2-a. lea: Check base register to profile stack pointer calculations accurately
        if (INS_IsLea(ins))
        {
            REG baseReg = INS_MemoryBaseReg(ins);
            BOOL isStackLea = (baseReg == REG_ESP || baseReg == REG_EBP);

            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)OnLea,
                IARG_EXPLICIT_MEMORY_EA,   ///< Address calculated by lea
                IARG_REG_VALUE, REG_ESP, IARG_BOOL, isStackLea, IARG_END);
        }

        // 2. Memory read (Source)
        if (INS_IsMemoryRead(ins))
        {
            BOOL isStackRead = INS_IsStackRead(ins); ///< Intel Pin API for stack read detection
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)OnMemRead,
                IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
                IARG_REG_VALUE, REG_ESP, IARG_BOOL, isStackRead, IARG_END);
        }

        // 3. Memory write (Destination, value handled in AFTER)
        if (INS_IsMemoryWrite(ins))
        {
            BOOL isStackWrite = INS_IsStackWrite(ins); ///< Intel Pin API for stack write detection (Fixed Bug)
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)OnMemWriteBefore,
                IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
                IARG_REG_VALUE, REG_ESP, IARG_END);

            if (INS_IsValidForIpointAfter(ins))
            {
                INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR)OnMemWriteAfter, IARG_BOOL, isStackWrite, IARG_END);
            }
        }
    }
}