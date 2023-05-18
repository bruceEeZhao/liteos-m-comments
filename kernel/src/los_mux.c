/*
 * Copyright (c) 2013-2019 Huawei Technologies Co., Ltd. All rights reserved.
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

#include "los_mux.h"
#include "los_config.h"
#include "los_debug.h"
#include "los_hook.h"
#include "los_interrupt.h"
#include "los_memory.h"
#include "los_sched.h"


#if (LOSCFG_BASE_IPC_MUX == 1)

LITE_OS_SEC_BSS       LosMuxCB*   g_allMux = NULL;
LITE_OS_SEC_DATA_INIT LOS_DL_LIST g_unusedMuxList;

/*****************************************************************************
 Function      : OsMuxInit
 Description  : Initializes the mutex
 Input        : None
 Output       : None
 Return       : LOS_OK on success, or error code on failure
 *****************************************************************************/
LITE_OS_SEC_TEXT_INIT UINT32 OsMuxInit(VOID)
{
    LosMuxCB *muxNode = NULL;
    UINT32 index;

    // 初始化全局双向循环链表
    LOS_ListInit(&g_unusedMuxList);

    if (LOSCFG_BASE_IPC_MUX_LIMIT == 0) {
        return LOS_ERRNO_MUX_MAXNUM_ZERO;
    }

    // 从动态内存中申请空间，共10个mutex
    g_allMux = (LosMuxCB *)LOS_MemAlloc(m_aucSysMem0, (LOSCFG_BASE_IPC_MUX_LIMIT * sizeof(LosMuxCB)));
    if (g_allMux == NULL) {
        return LOS_ERRNO_MUX_NO_MEMORY;
    }

    // 初始化，并使用尾插法插入g_unusedMuxList链表
    for (index = 0; index < LOSCFG_BASE_IPC_MUX_LIMIT; index++) {
        muxNode = ((LosMuxCB *)g_allMux) + index;
        muxNode->muxID = index;
        muxNode->owner = (LosTaskCB *)NULL;
        muxNode->muxStat = OS_MUX_UNUSED;
        LOS_ListTailInsert(&g_unusedMuxList, &muxNode->muxList);
    }
    return LOS_OK;
}

/*****************************************************************************
 Function     : LOS_MuxCreate
 Description  : Create a mutex
 Input        : muxHandle，用于写入被分配的muxCB的ID。
 Output       : muxHandle ------ Mutex operation handle
 Return       : LOS_OK on success, or error code on failure
 *****************************************************************************/
LITE_OS_SEC_TEXT_INIT UINT32 LOS_MuxCreate(UINT32 *muxHandle)
{
    UINT32 intSave;
    LosMuxCB *muxCreated = NULL;
    LOS_DL_LIST *unusedMux = NULL;
    UINT32 errNo;
    UINT32 errLine;

    if (muxHandle == NULL) {
        return LOS_ERRNO_MUX_PTR_NULL;
    }

    intSave = LOS_IntLock();
    // 如果没有可用的mutexCB，错误处理，返回
    if (LOS_ListEmpty(&g_unusedMuxList)) {
        LOS_IntRestore(intSave);
        OS_GOTO_ERR_HANDLER(LOS_ERRNO_MUX_ALL_BUSY);
    }

    // 链表中选择第一个元素，并从链表中删除
    unusedMux = LOS_DL_LIST_FIRST(&(g_unusedMuxList));
    LOS_ListDelete(unusedMux);

    // 对mutexCB属性进行赋值，state标记为used，初始化muxList链表
    muxCreated = (GET_MUX_LIST(unusedMux));
    muxCreated->muxCount = 0;
    muxCreated->muxStat = OS_MUX_USED;
    muxCreated->priority = 0;
    muxCreated->owner = (LosTaskCB *)NULL;
    LOS_ListInit(&muxCreated->muxList);

    // 把muxID赋值给muxHandle，使得用户可以根据muxHandle操作mutex
    *muxHandle = (UINT32)muxCreated->muxID;
    LOS_IntRestore(intSave);
    OsHookCall(LOS_HOOK_TYPE_MUX_CREATE, muxCreated);
    return LOS_OK;
ERR_HANDLER:
    OS_RETURN_ERROR_P2(errLine, errNo);
}

/*****************************************************************************
 Function     : LOS_MuxDelete
 Description  : Delete a mutex
 Input        : muxHandle ------Mutex operation handle
 Output       : None
 Return       : LOS_OK on success, or error code on failure
 *****************************************************************************/
LITE_OS_SEC_TEXT_INIT UINT32 LOS_MuxDelete(UINT32 muxHandle)
{
    UINT32 intSave;
    LosMuxCB *muxDeleted = NULL;
    UINT32 errNo;
    UINT32 errLine;

    // 检查ID是否合法
    if (muxHandle >= (UINT32)LOSCFG_BASE_IPC_MUX_LIMIT) {
        OS_GOTO_ERR_HANDLER(LOS_ERRNO_MUX_INVALID);
    }

    // 根据id获取mutexCB
    muxDeleted = GET_MUX(muxHandle);
    intSave = LOS_IntLock();

    // 如果状态是unused，返回错误
    if (muxDeleted->muxStat == OS_MUX_UNUSED) {
        LOS_IntRestore(intSave);
        OS_GOTO_ERR_HANDLER(LOS_ERRNO_MUX_INVALID);
    }

    // 如果muxList非空或muxCount不为0,表示仍然被使用，返回错误
    if ((!LOS_ListEmpty(&muxDeleted->muxList)) || muxDeleted->muxCount) {
        LOS_IntRestore(intSave);
        OS_GOTO_ERR_HANDLER(LOS_ERRNO_MUX_PENDED);
    }

    // 使用头插法，将mutexCB插入空闲链表，设置state为未使用
    LOS_ListAdd(&g_unusedMuxList, &muxDeleted->muxList);
    muxDeleted->muxStat = OS_MUX_UNUSED;

    LOS_IntRestore(intSave);

    OsHookCall(LOS_HOOK_TYPE_MUX_DELETE, muxDeleted);
    return LOS_OK;
ERR_HANDLER:
    OS_RETURN_ERROR_P2(errLine, errNo);
}

/**
 * @brief 合法性检查，不能是以下情况：
 *        1. mutexCB muxStat是未使用
 *        2. 处于中断处理中，g_intCount > 0 
 *        3. task处于锁定状态，g_losTaskLock > 0
 *        4. g_losTask.runTask 是系统任务
 * 
 * @param muxPended 
 * @return UINT32 
 */
STATIC_INLINE UINT32 OsMuxValidCheck(LosMuxCB *muxPended)
{
    if (muxPended->muxStat == OS_MUX_UNUSED) {
        return LOS_ERRNO_MUX_INVALID;
    }

    if (OS_INT_ACTIVE) {
        return LOS_ERRNO_MUX_IN_INTERR;
    }

    if (g_losTaskLock) {
        PRINT_ERR("!!!LOS_ERRNO_MUX_PEND_IN_LOCK!!!\n");
        return LOS_ERRNO_MUX_PEND_IN_LOCK;
    }

    if (g_losTask.runTask->taskStatus & OS_TASK_FLAG_SYSTEM_TASK) {
        return LOS_ERRNO_MUX_PEND_IN_SYSTEM_TASK;
    }

    return LOS_OK;
}

/*****************************************************************************
 Function     : LOS_MuxPend
 Description  : Specify the mutex P operation
 Input        : muxHandle ------ Mutex operation handleone
              : timeOut   ------- waiting time
 Output       : None
 Return       : LOS_OK on success, or error code on failure
 *****************************************************************************/
LITE_OS_SEC_TEXT UINT32 LOS_MuxPend(UINT32 muxHandle, UINT32 timeout)
{
    UINT32 intSave;
    LosMuxCB *muxPended = NULL;
    UINT32 retErr;
    LosTaskCB *runningTask = NULL;

    if (muxHandle >= (UINT32)LOSCFG_BASE_IPC_MUX_LIMIT) {
        OS_RETURN_ERROR(LOS_ERRNO_MUX_INVALID);
    }

    // 根据muxID获取mutexCB
    muxPended = GET_MUX(muxHandle);
    intSave = LOS_IntLock();
    // mutex前的合法性检查
    retErr = OsMuxValidCheck(muxPended);
    if (retErr) {
        goto ERROR_MUX_PEND;
    }

    runningTask = (LosTaskCB *)g_losTask.runTask;
    // 1.如果count==0,证明没有其他任务对其加锁
    if (muxPended->muxCount == 0) {
        muxPended->muxCount++;
        muxPended->owner = runningTask;
        muxPended->priority = runningTask->priority;
        LOS_IntRestore(intSave);
        goto HOOK;
    }

    // 2.虽然之前已经加锁，但是加锁的是自己，锁的可重入性
    if (muxPended->owner == runningTask) {
        muxPended->muxCount++;
        LOS_IntRestore(intSave);
        goto HOOK;
    }

    // 3. 之前已加锁，且不是自己，此时应该进行锁等待
    // 如果timeout==0,返回错误
    if (!timeout) {
        retErr = LOS_ERRNO_MUX_UNAVAILABLE;
        goto ERROR_MUX_PEND;
    }
    // 给taskMux赋值
    runningTask->taskMux = (VOID *)muxPended;

    // 如果mutexCB持有者的优先级的值 > 当前运行task的优先级（这里值越大则优先级越小）
    // 则修改mutexCB持有者的权限为当前运行task的权限，
    // 即如果进行锁等待的任务优先级大于mutex持有者的优先级，则提高持有者的优先级，优先级继承，解决优先级反转问题
    if (muxPended->owner->priority > runningTask->priority) {
        (VOID)OsSchedModifyTaskSchedParam(muxPended->owner, runningTask->priority);
    }

    // 将runTask加入muxPended等待队列
    OsSchedTaskWait(&muxPended->muxList, timeout);

    LOS_IntRestore(intSave);
    OsHookCall(LOS_HOOK_TYPE_MUX_PEND, muxPended, timeout);
    // 调度
    LOS_Schedule();

    intSave = LOS_IntLock();
    if (runningTask->taskStatus & OS_TASK_STATUS_TIMEOUT) {
        runningTask->taskStatus &= (~OS_TASK_STATUS_TIMEOUT);
        retErr = LOS_ERRNO_MUX_TIMEOUT;
        goto ERROR_MUX_PEND;
    }

    LOS_IntRestore(intSave);
    return LOS_OK;

HOOK:
    OsHookCall(LOS_HOOK_TYPE_MUX_PEND, muxPended, timeout);
    return LOS_OK;

ERROR_MUX_PEND:
    LOS_IntRestore(intSave);
    OS_RETURN_ERROR(retErr);
}

/*****************************************************************************
 Function     : LOS_MuxPost
 Description  : Specify the mutex V operation,
 Input        : muxHandle ------ Mutex operation handle
 Output       : None
 Return       : LOS_OK on success, or error code on failure
 *****************************************************************************/
LITE_OS_SEC_TEXT UINT32 LOS_MuxPost(UINT32 muxHandle)
{
    UINT32 intSave;
    LosMuxCB *muxPosted = GET_MUX(muxHandle);
    LosTaskCB *resumedTask = NULL;
    LosTaskCB *runningTask = NULL;

    intSave = LOS_IntLock();

    // muxId和状态校验
    if ((muxHandle >= (UINT32)LOSCFG_BASE_IPC_MUX_LIMIT) ||
        (muxPosted->muxStat == OS_MUX_UNUSED)) {
        LOS_IntRestore(intSave);
        OS_RETURN_ERROR(LOS_ERRNO_MUX_INVALID);
    }

    // 处于中断处理中，g_intCount > 0 
    if (OS_INT_ACTIVE) {
        LOS_IntRestore(intSave);
        OS_RETURN_ERROR(LOS_ERRNO_MUX_IN_INTERR);
    }

    runningTask = (LosTaskCB *)g_losTask.runTask;
    // 1. 如果mutex未被加锁，或持有者不是自己，返回错误
    if ((muxPosted->muxCount == 0) || (muxPosted->owner != runningTask)) {
        LOS_IntRestore(intSave);
        OS_RETURN_ERROR(LOS_ERRNO_MUX_INVALID);
    }

    // 2.如果解锁后，count仍大于0,返回LOS_OK
    if (--(muxPosted->muxCount) != 0) {
        LOS_IntRestore(intSave);
        OsHookCall(LOS_HOOK_TYPE_MUX_POST, muxPosted);
        return LOS_OK;
    }

    // 3. 解锁后，count==0
    // 如果持有者的优先级与muxPosted的优先级不同，则修改持有者的优先级为原始优先级
    if ((muxPosted->owner->priority) != muxPosted->priority) {
        (VOID)OsSchedModifyTaskSchedParam(muxPosted->owner, muxPosted->priority);
    }

    // 如果等待列表非空
    if (!LOS_ListEmpty(&muxPosted->muxList)) {
        // 取出第一个元素
        resumedTask = OS_TCB_FROM_PENDLIST(LOS_DL_LIST_FIRST(&(muxPosted->muxList)));

        muxPosted->muxCount = 1;
        muxPosted->owner = resumedTask; // 持有者设为resumedTask
        muxPosted->priority = resumedTask->priority; // 设置优先级
        resumedTask->taskMux = NULL;  // 修改为NULL

        OsSchedTaskWake(resumedTask); // 唤醒resumedTask

        LOS_IntRestore(intSave);
        OsHookCall(LOS_HOOK_TYPE_MUX_POST, muxPosted);
        LOS_Schedule();              // 调度
    } else {
        muxPosted->owner = NULL;
        LOS_IntRestore(intSave);
    }

    return LOS_OK;
}
#endif /* (LOSCFG_BASE_IPC_MUX == 1) */

