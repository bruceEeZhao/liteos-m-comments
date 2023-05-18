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

#include "los_event.h"
#include "los_hook.h"
#include "los_interrupt.h"
#include "los_task.h"
#include "los_sched.h"

/**
 * @brief 对传入的eventCB进行初始化
 * 
 * @param eventCB 
 * @return LITE_OS_SEC_TEXT_INIT 
 */
LITE_OS_SEC_TEXT_INIT UINT32 LOS_EventInit(PEVENT_CB_S eventCB)
{
    if (eventCB == NULL) {
        return LOS_ERRNO_EVENT_PTR_NULL;
    }
    eventCB->uwEventID = 0;
    // 初始化链表
    LOS_ListInit(&eventCB->stEventList);
    OsHookCall(LOS_HOOK_TYPE_EVENT_INIT, eventCB);
    return LOS_OK;
}

LITE_OS_SEC_TEXT UINT32 LOS_EventPoll(UINT32 *eventID, UINT32 eventMask, UINT32 mode)
{
    UINT32 ret = 0;
    UINT32 intSave;

    if (eventID == NULL) {
        return LOS_ERRNO_EVENT_PTR_NULL;
    }
    intSave = LOS_IntLock();
    // 如果mode是或
    if (mode & LOS_WAITMODE_OR) {
        // 如果其中一个事件发生了，获得事件id
        if ((*eventID & eventMask) != 0) {
            ret = *eventID & eventMask;
        }
    } else {
        // 如果全部事件都发生了，获得事件id
        if ((eventMask != 0) && (eventMask == (*eventID & eventMask))) {
            ret = *eventID & eventMask;
        }
    }
    // 如果mode是LOS_WAITMODE_CLR，清除该事件
    if (ret && (mode & LOS_WAITMODE_CLR)) {
        *eventID = *eventID & ~(ret);
    }
    LOS_IntRestore(intSave);
    return ret;
}

LITE_OS_SEC_TEXT STATIC_INLINE UINT32 OsEventReadParamCheck(PEVENT_CB_S eventCB, UINT32 eventMask, UINT32 mode)
{
    if (eventCB == NULL) {
        return LOS_ERRNO_EVENT_PTR_NULL;
    }
    // 未初始化
    if ((eventCB->stEventList.pstNext == NULL) || (eventCB->stEventList.pstPrev == NULL)) {
        return LOS_ERRNO_EVENT_NOT_INITIALIZED;
    }
    // mask == 0表示非法的任务
    if (eventMask == 0) {
        return LOS_ERRNO_EVENT_EVENTMASK_INVALID;
    }
    if (eventMask & LOS_ERRTYPE_ERROR) {
        return LOS_ERRNO_EVENT_SETBIT_INVALID;
    }

    // mode 即时OR又是AND
    // mode 不是AND OR CLR 中的任何一种，非法mode类型
    if (((mode & LOS_WAITMODE_OR) && (mode & LOS_WAITMODE_AND)) ||
        (mode & ~(LOS_WAITMODE_OR | LOS_WAITMODE_AND | LOS_WAITMODE_CLR)) ||
        !(mode & (LOS_WAITMODE_OR | LOS_WAITMODE_AND))) {
        return LOS_ERRNO_EVENT_FLAGS_INVALID;
    }
    return LOS_OK;
}

LITE_OS_SEC_TEXT UINT32 LOS_EventRead(PEVENT_CB_S eventCB, UINT32 eventMask, UINT32 mode, UINT32 timeOut)
{
    UINT32 ret;
    UINT32 intSave;
    LosTaskCB *runTsk = NULL;

    // 参数合法性校验
    ret = OsEventReadParamCheck(eventCB, eventMask, mode);
    if (ret != LOS_OK) {
        return ret;
    }
    // 正在执行中断
    if (OS_INT_ACTIVE) {
        return LOS_ERRNO_EVENT_READ_IN_INTERRUPT;
    }
    // 系统任务
    if (g_losTask.runTask->taskStatus & OS_TASK_FLAG_SYSTEM_TASK) {
        return LOS_ERRNO_EVENT_READ_IN_SYSTEM_TASK;
    }
    intSave = LOS_IntLock();
    ret = LOS_EventPoll(&(eventCB->uwEventID), eventMask, mode);
    OsHookCall(LOS_HOOK_TYPE_EVENT_READ, eventCB, eventMask, mode, timeOut);
    // ret == 0,表示事件没有发生，需要等待
    if (ret == 0) {
        // 不等待，直接返回
        if (timeOut == 0) {
            LOS_IntRestore(intSave);
            return ret;
        }

        if (g_losTaskLock) {
            LOS_IntRestore(intSave);
            return LOS_ERRNO_EVENT_READ_IN_LOCK;
        }
        runTsk = g_losTask.runTask;
        runTsk->eventMask = eventMask;
        runTsk->eventMode = mode;

        // 加入等待列表
        OsSchedTaskWait(&eventCB->stEventList, timeOut);
        LOS_IntRestore(intSave);
        LOS_Schedule();

        intSave = LOS_IntLock();
        // 如果超时，返回超时错误
        if (runTsk->taskStatus & OS_TASK_STATUS_TIMEOUT) {
            runTsk->taskStatus &= ~OS_TASK_STATUS_TIMEOUT;
            LOS_IntRestore(intSave);
            return LOS_ERRNO_EVENT_READ_TIMEOUT;
        }

        // 再次读取，看事件是否发生
        ret = LOS_EventPoll(&eventCB->uwEventID, eventMask, mode);
    }

    LOS_IntRestore(intSave);
    return ret;
}

LITE_OS_SEC_TEXT UINT32 LOS_EventWrite(PEVENT_CB_S eventCB, UINT32 events)
{
    LosTaskCB *resumedTask = NULL;
    LosTaskCB *nextTask = (LosTaskCB *)NULL;
    UINT32 intSave;
    UINT8 exitFlag = 0;
    if (eventCB == NULL) {
        return LOS_ERRNO_EVENT_PTR_NULL;
    }
    if ((eventCB->stEventList.pstNext == NULL) || (eventCB->stEventList.pstPrev == NULL)) {
        return LOS_ERRNO_EVENT_NOT_INITIALIZED;
    }
    if (events & LOS_ERRTYPE_ERROR) {
        return LOS_ERRNO_EVENT_SETBIT_INVALID;
    }
    intSave = LOS_IntLock();
    OsHookCall(LOS_HOOK_TYPE_EVENT_WRITE, eventCB, events);

    // 发生了一个事件，那么当前eventCB当前的状态应该是之前发生的状态与当前事件的 或
    eventCB->uwEventID |= events;

    // 如果事件等待列表非空
    if (!LOS_ListEmpty(&eventCB->stEventList)) {
        // 遍历等待链表
        for (resumedTask = LOS_DL_LIST_ENTRY((&eventCB->stEventList)->pstNext, LosTaskCB, pendList);
             &resumedTask->pendList != (&eventCB->stEventList);) {
            nextTask = LOS_DL_LIST_ENTRY(resumedTask->pendList.pstNext, LosTaskCB, pendList);

            // 如果task的mode是OR，判断是否其中一个事件发生
            // 如果task的mode是AND，判断是否全部事件发生
            // 若发生，唤醒task，加入全局就绪链表中
            if (((resumedTask->eventMode & LOS_WAITMODE_OR) && (resumedTask->eventMask & events) != 0) ||
                ((resumedTask->eventMode & LOS_WAITMODE_AND) &&
                 ((resumedTask->eventMask & eventCB->uwEventID) == resumedTask->eventMask))) {
                exitFlag = 1;

                OsSchedTaskWake(resumedTask);
            }
            resumedTask = nextTask;
        }

        // 如果有任务被唤醒，调度
        if (exitFlag == 1) {
            LOS_IntRestore(intSave);
            LOS_Schedule();
            return LOS_OK;
        }
    }

    LOS_IntRestore(intSave);
    return LOS_OK;
}

/**
 * @brief 销毁event列表，如果event列表非空则不能销毁
 * 
 * @param eventCB 
 * @return LITE_OS_SEC_TEXT_INIT 
 */
LITE_OS_SEC_TEXT_INIT UINT32 LOS_EventDestroy(PEVENT_CB_S eventCB)
{
    UINT32 intSave;
    if (eventCB == NULL) {
        return LOS_ERRNO_EVENT_PTR_NULL;
    }
    intSave = LOS_IntLock();
    
    // event列表非空则不能删除
    if (!LOS_ListEmpty(&eventCB->stEventList)) {
        LOS_IntRestore(intSave);
        return LOS_ERRNO_EVENT_SHOULD_NOT_DESTROYED;
    }
    eventCB->stEventList.pstNext = (LOS_DL_LIST *)NULL;
    eventCB->stEventList.pstPrev = (LOS_DL_LIST *)NULL;
    LOS_IntRestore(intSave);
    OsHookCall(LOS_HOOK_TYPE_EVENT_DESTROY, eventCB);
    return LOS_OK;
}

/**
 * @brief 根据eventMask设置uwEventID，可以实现清除某个任务或全部任务
 * 
 * @param eventCB 
 * @param eventMask 
 * @return LITE_OS_SEC_TEXT_MINOR 
 */
LITE_OS_SEC_TEXT_MINOR UINT32 LOS_EventClear(PEVENT_CB_S eventCB, UINT32 eventMask)
{
    UINT32 intSave;
    if (eventCB == NULL) {
        return LOS_ERRNO_EVENT_PTR_NULL;
    }
    OsHookCall(LOS_HOOK_TYPE_EVENT_CLEAR, eventCB, eventMask);
    intSave = LOS_IntLock();
    eventCB->uwEventID &= eventMask;
    LOS_IntRestore(intSave);
    return LOS_OK;
}
