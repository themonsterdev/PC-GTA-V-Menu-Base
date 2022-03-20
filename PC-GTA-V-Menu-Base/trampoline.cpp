#include "pch.h"
#include "trampoline.h"

// Voler des octets
SInstructions StealBytes(LPVOID pTarget)
{
    SInstructions instructions = {};
    instructions.m_uNumBytes = RESET_SIZE;
    instructions.m_uNumInstructions = 1;

    instructions.m_instructions[0].size = 5;
    memcpy(instructions.m_instructions[0].bytes, pTarget, RESET_SIZE);

    // replace instructions in target func wtih NOPs
    memset(pTarget, 0x90, instructions.m_uNumBytes);

    return instructions;
}

uint32_t BuildTrampoline(LPVOID pTarget, LPVOID pDstMemForTrampoline)
{
    SInstructions stolenInstrs = StealBytes(pTarget);

    uint8_t* stolenByteMemory = (uint8_t*)pDstMemForTrampoline;
    uint8_t* jumpBackMemory = stolenByteMemory + stolenInstrs.m_uNumBytes;  // m_uNumBytes: 4 + 4 = 8
    uint8_t* absoluteTableMemory = jumpBackMemory + (RESET_SIZE + 5);            // 13 is the size of a 64 bit mov/jmp instruction pair
    // 4 + 5 = 9 // or 8 + 5 = 13

    for (uint32_t i = 0; i < stolenInstrs.m_uNumInstructions; ++i)                  // stolenInstrs.m_uNumInstructions: x + y = 2
    {
        SInstruction& inst = stolenInstrs.m_instructions[i];

        memcpy(stolenByteMemory, inst.bytes, inst.size);    // copy x and y
        stolenByteMemory += inst.size;                      // increment + 4 byte
    }

    WriteAbsoluteJump64(jumpBackMemory, (uint8_t*)pTarget + 5);

    return uint32_t(absoluteTableMemory - (uint8_t*)pDstMemForTrampoline);
}
