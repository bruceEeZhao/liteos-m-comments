/*
 * Copyright (c) 2013-2020, Huawei Technologies Co., Ltd. All rights reserved.
 * Copyright (c) 2020-2021 Huawei Device Co., Ltd. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 *    conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list
 *    of conditions and the following disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used
 *    to endorse or promote products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _LOS_EXC_S
#define _LOS_EXC_S
#include "soc.h"

.macro PUSH_CALLER_REG
    addi sp, sp, -(32 * REGBYTES)
    SREG  t6, 2 * REGBYTES(sp)
    SREG  t5, 3 * REGBYTES(sp)
    SREG  t4, 4 * REGBYTES(sp)
    SREG  t3, 5 * REGBYTES(sp)
    SREG  t2, 6 * REGBYTES(sp)
    SREG  t1, 7 * REGBYTES(sp)
    SREG  t0, 8 * REGBYTES(sp)
    SREG  a7, 18 * REGBYTES(sp)
    SREG  a6, 19 * REGBYTES(sp)
    SREG  a5, 20 * REGBYTES(sp)
    SREG  a4, 21 * REGBYTES(sp)
    SREG  a3, 22 * REGBYTES(sp)
    SREG  a2, 23 * REGBYTES(sp)
    SREG  a1, 24 * REGBYTES(sp)
    SREG  a0, 25 * REGBYTES(sp)
    SREG  ra, 31 * REGBYTES(sp)
    csrr  t0, mstatus
    SREG  t0, 16 * REGBYTES(sp)
    csrr  t0, mepc
    SREG  t0, 17 * REGBYTES(sp)
.endm

.macro POP_CALLER_REG
    LREG  t0, 16 * REGBYTES(sp)
    csrw  mstatus, t0
    LREG  t0, 17 * REGBYTES(sp)
    csrw  mepc, t0
    LREG  t6, 2 * REGBYTES(sp)
    LREG  t5, 3 * REGBYTES(sp)
    LREG  t4, 4 * REGBYTES(sp)
    LREG  t3, 5 * REGBYTES(sp)
    LREG  t2, 6 * REGBYTES(sp)
    LREG  t1, 7 * REGBYTES(sp)
    LREG  t0, 8 * REGBYTES(sp)
    LREG  a7, 18 * REGBYTES(sp)
    LREG  a6, 19 * REGBYTES(sp)
    LREG  a5, 20 * REGBYTES(sp)
    LREG  a4, 21 * REGBYTES(sp)
    LREG  a3, 22 * REGBYTES(sp)
    LREG  a2, 23 * REGBYTES(sp)
    LREG  a1, 24 * REGBYTES(sp)
    LREG  a0, 25 * REGBYTES(sp)
    LREG  ra, 31 * REGBYTES(sp)
    addi sp, sp, 32 * REGBYTES
.endm

.macro PUSH_CALLEE_REG
   SREG  s11, 9 * REGBYTES(sp)
   SREG  s10, 10 * REGBYTES(sp)
   SREG  s9, 11 * REGBYTES(sp)
   SREG  s8, 12 * REGBYTES(sp)
   SREG  s7, 13 * REGBYTES(sp)
   SREG  s6, 14 * REGBYTES(sp)
   SREG  s5, 15 * REGBYTES(sp)
   SREG  s4, 26 * REGBYTES(sp)
   SREG  s3, 27 * REGBYTES(sp)
   SREG  s2, 28 * REGBYTES(sp)
   SREG  s1, 29 * REGBYTES(sp)
   SREG  s0, 30 * REGBYTES(sp)
.endm

.macro POP_ALL_REG
    LREG  t6, 2 * REGBYTES(sp)
    LREG  t5, 3 * REGBYTES(sp)
    LREG  t4, 4 * REGBYTES(sp)
    LREG  t3, 5 * REGBYTES(sp)
    LREG  t2, 6 * REGBYTES(sp)
    LREG  t1, 7 * REGBYTES(sp)
    LREG  t0, 8 * REGBYTES(sp)
    LREG  s11, 9 * REGBYTES(sp)
    LREG  s10, 10 * REGBYTES(sp)
    LREG  s9, 11 * REGBYTES(sp)
    LREG  s8, 12 * REGBYTES(sp)
    LREG  s7, 13 * REGBYTES(sp)
    LREG  s6, 14 * REGBYTES(sp)
    LREG  s5, 15 * REGBYTES(sp)
    LREG  a7, 18 * REGBYTES(sp)
    LREG  a6, 19 * REGBYTES(sp)
    LREG  a5, 20 * REGBYTES(sp)
    LREG  a4, 21 * REGBYTES(sp)
    LREG  a3, 22 * REGBYTES(sp)
    LREG  a2, 23 * REGBYTES(sp)
    LREG  a1, 24 * REGBYTES(sp)
    LREG  a0, 25 * REGBYTES(sp)
    LREG  s4, 26 * REGBYTES(sp)
    LREG  s3, 27 * REGBYTES(sp)
    LREG  s2, 28 * REGBYTES(sp)
    LREG  s1, 29 * REGBYTES(sp)
    LREG  s0, 30 * REGBYTES(sp)
    LREG  ra, 31 * REGBYTES(sp)
    addi  sp, sp, 32 * REGBYTES
.endm

.section .interrupt.text
.extern HalExcEntry
.extern g_excInfo
.global HalTrapEntry
.align 4
HalTrapEntry:
    PUSH_CALLEE_REG
    addi  sp, sp, -(4 * REGBYTES)
    sw    a0, 0 * REGBYTES(sp)
    csrr  t0, mtval
    sw    t0, 1 * REGBYTES(sp)
    csrr  t0, medeleg
    sw    t0, 2 * REGBYTES(sp)
    sw    gp, 3 * REGBYTES(sp)
    mv    a0, sp
    csrw  mscratch, sp
    la    t0, g_excInfo
    lh    t1, 0(t0)
    bnez  t1, 1f
    la    sp, __except_stack_top
1:
    addi  t1, t1, 0x1
    sh    t1, 0(t0)
    call  HalExcEntry
    la    t0, g_excInfo
    sh    zero, 0(t0)
    csrr  sp, mscratch
    addi  sp, sp, 4 * REGBYTES
    lw    t0, 16 * REGBYTES(sp)
    csrw  mstatus, t0
    lw    t0, 17 * REGBYTES(sp)
    csrw  mepc, t0
    POP_ALL_REG
    mret


.section .interrupt.HalTrapVector.text
.extern HalTrapEntry
.extern HalIrqEndCheckNeedSched
.global HalTrapVector
.equ TRAP_INTERRUPT_MODE_MASK, 0x80000000
.align 4
HalTrapVector:
    PUSH_CALLER_REG   # 保存现场
    csrr  a0, mcause  # Machine trap cause.寄存器最高位表示中断位，为1表示是一个中断
    li    a1, TRAP_INTERRUPT_MODE_MASK  # a1 = 0x80000000
    li    a2, MCAUSE_INT_ID_MASK # a2 = 0x7FFFFFF
    and   a1, a0, a1 
    and   a0, a2, a0
    beqz  a1, HalTrapEntry # 最高位是0,表示是一个trap，进入trap处理
    csrw  mscratch, sp     # mscratch用于保存指向机器模式hart本地上下文空间的指针，并在进入m模式trap处理程序时与用户寄存器进行交换
    la    sp, __start_and_irq_stack_top
    jal   HalHwiInterruptDone
    csrr  sp, mscratch     # 恢复sp
    call  HalIrqEndCheckNeedSched

    POP_CALLER_REG  # 恢复现场
    mret
#endif /* _LOS_TRAP_S */
