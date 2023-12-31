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

#include "los_sched.h"
#include "los_task.h"
#include "los_tick.h"
#include "los_swtmr.h"
#include "los_debug.h"
#include "los_hook.h"
#if (LOSCFG_KERNEL_PM == 1)
#include "los_pm.h"
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

#define OS_PRIORITY_QUEUE_NUM      32
#define PRIQUEUE_PRIOR0_BIT        0x80000000U
#define OS_SCHED_TIME_SLICES       ((LOSCFG_BASE_CORE_TIMESLICE_TIMEOUT * OS_SYS_NS_PER_US) / OS_NS_PER_CYCLE)
#define OS_TIME_SLICE_MIN          (INT32)((50 * OS_SYS_NS_PER_US) / OS_NS_PER_CYCLE) /* 50us */
#define OS_TICK_RESPONSE_TIME_MAX  LOSCFG_BASE_CORE_TICK_RESPONSE_MAX
#define OS_TICK_RESPONSE_PRECISION (UINT32)((OS_SCHED_MINI_PERIOD * 75) / 100)
#if (LOSCFG_BASE_CORE_TICK_RESPONSE_MAX == 0)
#error "Must specify the maximum value that tick timer counter supports!"
#endif

#define OS_TASK_BLOCKED_STATUS (OS_TASK_STATUS_PEND | OS_TASK_STATUS_SUSPEND | \
                                OS_TASK_STATUS_EXIT | OS_TASK_STATUS_UNUSED)

STATIC SchedScan  g_swtmrScan = NULL;
STATIC SortLinkAttribute *g_taskSortLinkList = NULL;
STATIC LOS_DL_LIST g_priQueueList[OS_PRIORITY_QUEUE_NUM];
STATIC UINT32 g_queueBitmap;

STATIC UINT32 g_schedResponseID = 0;
STATIC UINT16 g_tickIntLock = 0;
STATIC UINT64 g_schedResponseTime = OS_SCHED_MAX_RESPONSE_TIME;

/**
 * @brief 重置g_schedResponseTime ，如果responseTime <= g_schedResponseTime
 * 
 * @param responseTime 
 * @return VOID 
 */
VOID OsSchedResetSchedResponseTime(UINT64 responseTime)
{
    if (responseTime <= g_schedResponseTime) {
        g_schedResponseTime = OS_SCHED_MAX_RESPONSE_TIME;
    }
}

/// @brief 更新时间片taskCB->timeSlice -= incTime，更新taskCB->startTime = currTime
/// @param taskCB 
/// @param currTime 
/// @return 
STATIC INLINE VOID OsTimeSliceUpdate(LosTaskCB *taskCB, UINT64 currTime)
{
    LOS_ASSERT(currTime >= taskCB->startTime);

    INT32 incTime = currTime - taskCB->startTime;
    if (taskCB->taskID != g_idleTaskID) {
        taskCB->timeSlice -= incTime;
    }
    taskCB->startTime = currTime;
}

STATIC INLINE VOID OsSchedSetNextExpireTime(UINT32 responseID, UINT64 taskEndTime)
{
    UINT64 nextResponseTime;
    BOOL isTimeSlice = FALSE;
    // 获取当前时间
    UINT64 currTime = OsGetCurrSchedTimeCycle();
    UINT64 nextExpireTime = OsGetNextExpireTime(currTime, OS_TICK_RESPONSE_PRECISION);
    /* The response time of the task time slice is aligned to the next response time in the delay queue */
    // 如果下一个过期时间大于结束时间且 下一个过期时间 - 结束时间大于最小调度间隔，则设置过期时间为结束时间
    if ((nextExpireTime > taskEndTime) && ((nextExpireTime - taskEndTime) > OS_SCHED_MINI_PERIOD)) {
        nextExpireTime = taskEndTime;
        isTimeSlice = TRUE;
    }

    if ((g_schedResponseTime <= nextExpireTime) ||
        ((g_schedResponseTime - nextExpireTime) < OS_TICK_RESPONSE_PRECISION)) {
        return;
    }

    if (isTimeSlice) {
        /* The expiration time of the current system is the thread's slice expiration time */
        g_schedResponseID = responseID;
    } else {
        g_schedResponseID = OS_INVALID;
    }

    nextResponseTime = nextExpireTime - currTime;
    if (nextResponseTime < OS_TICK_RESPONSE_PRECISION) {
        nextResponseTime = OS_TICK_RESPONSE_PRECISION;
    }
    g_schedResponseTime = currTime + OsTickTimerReload(nextResponseTime);
}

VOID OsSchedUpdateExpireTime(VOID)
{
    UINT64 endTime;
    BOOL isPmMode = FALSE;
    LosTaskCB *runTask = g_losTask.runTask;

    if (!g_taskScheduled || g_tickIntLock) {
        return;
    }

#if (LOSCFG_KERNEL_PM == 1)
    isPmMode = OsIsPmMode();
#endif
    if ((runTask->taskID != g_idleTaskID) && !isPmMode) {
        INT32 timeSlice = (runTask->timeSlice <= OS_TIME_SLICE_MIN) ? (INT32)OS_SCHED_TIME_SLICES : runTask->timeSlice;
        endTime = runTask->startTime + timeSlice;
    } else {
        endTime = OS_SCHED_MAX_RESPONSE_TIME - OS_TICK_RESPONSE_PRECISION;
    }
    OsSchedSetNextExpireTime(runTask->taskID, endTime);
}

STATIC INLINE VOID OsSchedPriQueueEnHead(LOS_DL_LIST *priqueueItem, UINT32 priority)
{
    /*
     * Task control blocks are inited as zero. And when task is deleted,
     * and at the same time would be deleted from priority queue or
     * other lists, task pend node will restored as zero.
     */
    if (LOS_ListEmpty(&g_priQueueList[priority])) {
        // 意思是优先级为priority的队列要加入元素，不空
        g_queueBitmap |= PRIQUEUE_PRIOR0_BIT >> priority;
    }

    // 把task加入优先级为priority的队列头部
    LOS_ListAdd(&g_priQueueList[priority], priqueueItem);
}

STATIC INLINE VOID OsSchedPriQueueEnTail(LOS_DL_LIST *priqueueItem, UINT32 priority)
{
    if (LOS_ListEmpty(&g_priQueueList[priority])) {
        // 意思是优先级为priority的队列要加入元素，不空
        g_queueBitmap |= PRIQUEUE_PRIOR0_BIT >> priority;
    }

    // 把task加入优先级为priority的队列尾部
    LOS_ListTailInsert(&g_priQueueList[priority], priqueueItem);
}

/// @brief 将任务从优先级队列删除，如果删除后该队列为空，则修改g_queueBitmap
/// @param priqueueItem 
/// @param priority 
/// @return 
STATIC INLINE VOID OsSchedPriQueueDelete(LOS_DL_LIST *priqueueItem, UINT32 priority)
{
    LOS_ListDelete(priqueueItem);
    if (LOS_ListEmpty(&g_priQueueList[priority])) {
        g_queueBitmap &= ~(PRIQUEUE_PRIOR0_BIT >> priority);
    }
}

/**
 * @brief 唤醒超时等待的task，将task从之前的等待链表中删除，可能是事件、信号等待链表等，如果状态不是SUSPEND，加入就绪队列
 * 
 * @param taskCB 
 * @param needSchedule 
 * @return VOID 
 */
STATIC INLINE VOID OsSchedWakePendTimeTask(LosTaskCB *taskCB, BOOL *needSchedule)
{
    UINT16 tempStatus = taskCB->taskStatus;
    // 如果状态是PEND或DELAY，取消task的PEND，PEND_TIME,DELAY状态
    if (tempStatus & (OS_TASK_STATUS_PEND | OS_TASK_STATUS_DELAY)) {
        taskCB->taskStatus &= ~(OS_TASK_STATUS_PEND | OS_TASK_STATUS_PEND_TIME | OS_TASK_STATUS_DELAY);
        if (tempStatus & OS_TASK_STATUS_PEND) {
            taskCB->taskStatus |= OS_TASK_STATUS_TIMEOUT;
            // 将task从之前的等待链表中删除，可能是事件、信号等待链表等
            LOS_ListDelete(&taskCB->pendList);
            taskCB->taskMux = NULL;
            taskCB->taskSem = NULL;
        }

        // 如果状态不是SUSPEND，加入就绪队列
        if (!(tempStatus & OS_TASK_STATUS_SUSPEND)) {
            OsSchedTaskEnQueue(taskCB);
            *needSchedule = TRUE;
        }
    }
}

/**
 * @brief 每次时钟中断，都会检查sortlist，把其中超时的任务从链表中删除，并加入到就绪队列
 * 
 * @return false: 不需要调度
 *         true： 需要调度
 */
STATIC INLINE BOOL OsSchedScanTimerList(VOID)
{
    BOOL needSchedule = FALSE;
    LOS_DL_LIST *listObject = &g_taskSortLinkList->sortLink;
    /*
     * When task is pended with timeout, the task block is on the timeout sortlink
     * (per cpu) and ipc(mutex,sem and etc.)'s block at the same time, it can be waken
     * up by either timeout or corresponding ipc it's waiting.
     *
     * Now synchronize sortlink procedure is used, therefore the whole task scan needs
     * to be protected, preventing another core from doing sortlink deletion at same time.
     */

    if (LOS_ListEmpty(listObject)) {
        return needSchedule;
    }

    SortLinkList *sortList = LOS_DL_LIST_ENTRY(listObject->pstNext, SortLinkList, sortLinkNode);
    UINT64 currTime = OsGetCurrSchedTimeCycle();
    // 遍历链表直到sortList->responseTime > 当前时间，从sortlist中删除，并添加到就绪队列中
    while (sortList->responseTime <= currTime) {
        LosTaskCB *taskCB = LOS_DL_LIST_ENTRY(sortList, LosTaskCB, sortList);
        OsDeleteNodeSortLink(&taskCB->sortList);
        OsSchedWakePendTimeTask(taskCB, &needSchedule);
        if (LOS_ListEmpty(listObject)) {
            break;
        }

        sortList = LOS_DL_LIST_ENTRY(listObject->pstNext, SortLinkList, sortLinkNode);
    }

    return needSchedule;
}

/// @brief 将任务加入优先级队列中，如果时间片大于最小时间片，插入头部，否则（时间片用完）插入尾部，保证同级别的其他任务可以执行
/// @param taskCB 
/// @return VOID
VOID OsSchedTaskEnQueue(LosTaskCB *taskCB)
{   
    // 断言：task状态应该是非ready
    LOS_ASSERT(!(taskCB->taskStatus & OS_TASK_STATUS_READY));

    if (taskCB->taskID != g_idleTaskID) {
        if (taskCB->timeSlice > OS_TIME_SLICE_MIN) {
            // 如果时间片大于最小时间片，则把task加入优先级为priority的队列中。
            OsSchedPriQueueEnHead(&taskCB->pendList, taskCB->priority);
        } else { // 时间片用完
            taskCB->timeSlice = OS_SCHED_TIME_SLICES;
            OsSchedPriQueueEnTail(&taskCB->pendList, taskCB->priority);
        }
        OsHookCall(LOS_HOOK_TYPE_MOVEDTASKTOREADYSTATE, taskCB);
    }

    taskCB->taskStatus &= ~(OS_TASK_STATUS_PEND | OS_TASK_STATUS_SUSPEND |
                            OS_TASK_STATUS_DELAY | OS_TASK_STATUS_PEND_TIME);

    taskCB->taskStatus |= OS_TASK_STATUS_READY;
}

/// @brief 如果任务是就绪态，则将该任务从优先级队列删除，并取消就绪态
/// @param taskCB 
/// @return 
VOID OsSchedTaskDeQueue(LosTaskCB *taskCB)
{
    // 如果任务是就绪态，将任务从优先级队列删除
    if (taskCB->taskStatus & OS_TASK_STATUS_READY) {
        if (taskCB->taskID != g_idleTaskID) {
            OsSchedPriQueueDelete(&taskCB->pendList, taskCB->priority);
        }
        // 取消就绪态
        taskCB->taskStatus &= ~OS_TASK_STATUS_READY;
    }
}

VOID OsSchedTaskExit(LosTaskCB *taskCB)
{
    if (taskCB->taskStatus & OS_TASK_STATUS_READY) {
        OsSchedTaskDeQueue(taskCB);
    } else if (taskCB->taskStatus & OS_TASK_STATUS_PEND) {
        LOS_ListDelete(&taskCB->pendList);
        taskCB->taskStatus &= ~OS_TASK_STATUS_PEND;
    }

    if (taskCB->taskStatus & (OS_TASK_STATUS_DELAY | OS_TASK_STATUS_PEND_TIME)) {
        OsDeleteSortLink(&taskCB->sortList);
        taskCB->taskStatus &= ~(OS_TASK_STATUS_DELAY | OS_TASK_STATUS_PEND_TIME);
    }
}

/**
 * @brief 设置当前task g_losTask.runTask 时间片为0
 * 
 * @return VOID 
 */
VOID OsSchedYield(VOID)
{
    LosTaskCB *runTask = g_losTask.runTask;

    runTask->timeSlice = 0;
}

/**
 * @brief 设置状态为DELAY，设置等待时间
 * 
 * @param runTask 
 * @param tick 
 * @return VOID 
 */
VOID OsSchedDelay(LosTaskCB *runTask, UINT32 tick)
{
    runTask->taskStatus |= OS_TASK_STATUS_DELAY;
    runTask->waitTimes = tick;
}

VOID OsSchedTaskWait(LOS_DL_LIST *list, UINT32 ticks)
{
    LosTaskCB *runTask = g_losTask.runTask;

    runTask->taskStatus |= OS_TASK_STATUS_PEND;
    LOS_ListTailInsert(list, &runTask->pendList);

    // ticks != LOS_WAIT_FOREVER, ticks有效，设置runtask的waittimes
    if (ticks != LOS_WAIT_FOREVER) {
        runTask->taskStatus |= OS_TASK_STATUS_PEND_TIME;
        runTask->waitTimes = ticks;
    }
}

/**
 * @brief 取消PEND标志，
 *        1. 如果状态是PEND_TIME，则将task从sortList中删除
 *        2. 将resumed的task加入优先级队列中--唤醒一个task
 * 
 * @param resumedTask 
 * @return VOID 
 */
VOID OsSchedTaskWake(LosTaskCB *resumedTask)
{
    LOS_ListDelete(&resumedTask->pendList);
    // 取消 PEND 状态
    resumedTask->taskStatus &= ~OS_TASK_STATUS_PEND;

    if (resumedTask->taskStatus & OS_TASK_STATUS_PEND_TIME) {
        // 如果状态是PEND_TIME，需要将节点从sortlist中删除并取消该状态
        OsDeleteSortLink(&resumedTask->sortList);
        resumedTask->taskStatus &= ~OS_TASK_STATUS_PEND_TIME;
    }

    if (!(resumedTask->taskStatus & OS_TASK_STATUS_SUSPEND) &&
        !(resumedTask->taskStatus & OS_TASK_STATUS_RUNNING)) {
        OsSchedTaskEnQueue(resumedTask);
    }
}

/**
 * @brief 设置task->sortList->responseTime，设置status为FREEZE
 * 
 * @param taskCB 
 * @return STATIC 
 */
STATIC VOID OsSchedFreezeTask(LosTaskCB *taskCB)
{
    // 获取 responseTime
    UINT64 responseTime = GET_SORTLIST_VALUE(&taskCB->sortList);
    // 从sortlist删除task
    OsDeleteSortLink(&taskCB->sortList);
    SET_SORTLIST_VALUE(&taskCB->sortList, responseTime);
    // 设置task status
    taskCB->taskStatus |= OS_TASK_FLAG_FREEZE;
    return;
}

STATIC VOID OsSchedUnfreezeTask(LosTaskCB *taskCB)
{
    UINT64 currTime, responseTime;
    UINT32 remainTick;

    taskCB->taskStatus &= ~OS_TASK_FLAG_FREEZE;
    currTime = OsGetCurrSchedTimeCycle();
    responseTime = GET_SORTLIST_VALUE(&taskCB->sortList);
    if (responseTime > currTime) {
        remainTick = ((responseTime - currTime) + OS_CYCLE_PER_TICK - 1) / OS_CYCLE_PER_TICK;
        OsAdd2SortLink(&taskCB->sortList, currTime, remainTick, OS_SORT_LINK_TASK);
        return;
    }

    SET_SORTLIST_VALUE(&taskCB->sortList, OS_SORT_LINK_INVALID_TIME);
    if (taskCB->taskStatus & OS_TASK_STATUS_PEND) {
        LOS_ListDelete(&taskCB->pendList);
    }
    taskCB->taskStatus &= ~(OS_TASK_STATUS_DELAY | OS_TASK_STATUS_PEND_TIME | OS_TASK_STATUS_PEND);
    return;
}

/**
 * @brief 从优先级队列中删除task，设置status为suspend
 * 
 * @param taskCB 
 * @return VOID 
 */
VOID OsSchedSuspend(LosTaskCB *taskCB)
{
    BOOL isPmMode = FALSE;
    if (taskCB->taskStatus & OS_TASK_STATUS_READY) {
        // 从优先级队列中删除该任务
        OsSchedTaskDeQueue(taskCB);
    }

#if (LOSCFG_KERNEL_PM == 1)
    isPmMode = OsIsPmMode();
#endif
    // 如果 status 是 pend_time 或 DELAY
    if ((taskCB->taskStatus & (OS_TASK_STATUS_PEND_TIME | OS_TASK_STATUS_DELAY)) && isPmMode) {
        // 设置task->sortList->responseTime，设置status为FREEZE
        OsSchedFreezeTask(taskCB);
    }

    // 设置status为suspend
    taskCB->taskStatus |= OS_TASK_STATUS_SUSPEND;
    OsHookCall(LOS_HOOK_TYPE_MOVEDTASKTOSUSPENDEDLIST, taskCB);
}

/**
 * @brief 取消task 的suspend状态，如果状态不是DELAY 或 pend，把task加入优先级队列中
 * 
 * @param taskCB 
 * @return BOOL 
 */
BOOL OsSchedResume(LosTaskCB *taskCB)
{
    if (taskCB->taskStatus & OS_TASK_FLAG_FREEZE) {
        OsSchedUnfreezeTask(taskCB);
    }
    
    // 取消suspend状态
    taskCB->taskStatus &= (~OS_TASK_STATUS_SUSPEND);
    // 如果状态不是DELAY 或 pend，把task加入优先级队列中, 返回TRUE
    if (!(taskCB->taskStatus & (OS_TASK_STATUS_DELAY | OS_TASK_STATUS_PEND))) {
        OsSchedTaskEnQueue(taskCB);
        return TRUE;
    }

    return FALSE;
}

/**
 * @brief 设置task优先级，如果task状态是READY或RUNNING，返回TRUE
 * 
 * @param taskCB 
 * @param priority 
 * @return BOOL 
 */
BOOL OsSchedModifyTaskSchedParam(LosTaskCB *taskCB, UINT16 priority)
{
    if (taskCB->taskStatus & OS_TASK_STATUS_READY) {
        OsSchedTaskDeQueue(taskCB);
        taskCB->priority = priority;
        OsSchedTaskEnQueue(taskCB);
        return TRUE;
    }

    taskCB->priority = priority;
    OsHookCall(LOS_HOOK_TYPE_TASK_PRIMODIFY, taskCB, taskCB->priority);
    if (taskCB->taskStatus & OS_TASK_STATUS_RUNNING) {
        return TRUE;
    }

    return FALSE;
}

VOID OsSchedSetIdleTaskSchedParam(LosTaskCB *idleTask)
{
    OsSchedTaskEnQueue(idleTask);
}

UINT32 OsSchedSwtmrScanRegister(SchedScan func)
{
    if (func == NULL) {
        return LOS_NOK;
    }

    g_swtmrScan = func;
    return LOS_OK;
}

UINT32 OsTaskNextSwitchTimeGet(VOID)
{
    UINT32 intSave = LOS_IntLock();
    UINT32 ticks = OsSortLinkGetNextExpireTime(g_taskSortLinkList);
    LOS_IntRestore(intSave);
    return ticks;
}

UINT64 OsSchedGetNextExpireTime(UINT64 startTime)
{
    return OsGetNextExpireTime(startTime, OS_TICK_RESPONSE_PRECISION);
}

/**
 * @brief 初始化优先级队列（32个）
 * 
 * @return UINT32 
 */
UINT32 OsSchedInit(VOID)
{
    UINT16 pri;
    // 初始化每一个优先级队列双向链表，前向后向指针均指向本身
    for (pri = 0; pri < OS_PRIORITY_QUEUE_NUM; pri++) {
        LOS_ListInit(&g_priQueueList[pri]);
    }
    // 某一位为1表示该下标优先级队列有任务
    g_queueBitmap = 0;

    // g_taskSortLinkList = g_taskSortLink
    g_taskSortLinkList = OsGetSortLinkAttribute(OS_SORT_LINK_TASK);
    if (g_taskSortLinkList == NULL) {
        return LOS_NOK;
    }

    // 初始化成员 sortLink， g_taskSortLinkList 中只有一个成员 LOS_DL_LIST sortLink;
    OsSortLinkInit(g_taskSortLinkList);
    // 初始化调度响应时间为最大值，设置 g_schedResponseTime 为 ((UINT64)-1)
    g_schedResponseTime = OS_SCHED_MAX_RESPONSE_TIME;

    return LOS_OK;
}

/**
 * @brief 选取一个任务
 *        1. 如果g_queueBitmap不为0,则获取优先级最高的队列中的一个任务（pendlist），从优先级队列（32个优先级）中
 *        2. 否则根据TaskId（下标）从task数组中获取一个task
 * 
 * @return LosTaskCB* 
 */
LosTaskCB *OsGetTopTask(VOID)
{
    UINT32 priority;
    LosTaskCB *newTask = NULL;
    if (g_queueBitmap) {
        // CLZ 统计最高位0的个数
        priority = CLZ(g_queueBitmap);
        newTask = LOS_DL_LIST_ENTRY(((LOS_DL_LIST *)&g_priQueueList[priority])->pstNext, LosTaskCB, pendList);
    } else {
        newTask = OS_TCB_FROM_TID(g_idleTaskID);
    }

    return newTask;
}

VOID OsSchedStart(VOID)
{
    PRINTK("Entering scheduler\n");

    (VOID)LOS_IntLock();
    // 获取就绪队列中优先级最高的任务
    LosTaskCB *newTask = OsGetTopTask();

    // 设置为运行状态
    newTask->taskStatus |= OS_TASK_STATUS_RUNNING;
    // newtask和runtask均设置为 newtask
    g_losTask.newTask = newTask;
    g_losTask.runTask = g_losTask.newTask;

    // 设置开始运行时间
    newTask->startTime = OsGetCurrSchedTimeCycle();
    // 从就绪队列中删除
    OsSchedTaskDeQueue(newTask);

    OsTickSysTimerStartTimeSet(newTask->startTime);

    OsSwtmrResponseTimeReset(newTask->startTime);

    /* Initialize the schedule timeline and enable scheduling */
    g_taskScheduled = TRUE;

    g_schedResponseTime = OS_SCHED_MAX_RESPONSE_TIME;
    g_schedResponseID = OS_INVALID;
    // 设置task过期时间
    OsSchedSetNextExpireTime(newTask->taskID, newTask->startTime + newTask->timeSlice);
}

/**
 * @brief 判断是否需要进行task switch，首先把runtask插入就绪队列（如果不处于PEND_TIME,DELAY,BLOCK状态），
 *        然后选择最高优先级的任务作为newtask，如果runtask和newtask相同则不需要切换，否则，切换，
 *        这种切换逻辑保证了最高优先级的任务会优先执行
 * 
 * @return true： 需要switch
 *         false: 不需要switch
 */
BOOL OsSchedTaskSwitch(VOID)
{
    UINT64 endTime;
    BOOL isTaskSwitch = FALSE;
    LosTaskCB *runTask = g_losTask.runTask;
    // 更新runtask的时间片，减去运行的时间片，开始时间设置为当前时间
    OsTimeSliceUpdate(runTask, OsGetCurrSchedTimeCycle());

    // 如果任务处于pend_time或delay状态
    if (runTask->taskStatus & (OS_TASK_STATUS_PEND_TIME | OS_TASK_STATUS_DELAY)) {
        // 按task responseTime大小顺序插入g_taskSortLink有序链表，head->next 是最小的
        OsAdd2SortLink(&runTask->sortList, runTask->startTime, runTask->waitTimes, OS_SORT_LINK_TASK);
    } else if (!(runTask->taskStatus & OS_TASK_BLOCKED_STATUS)) { // 阻塞状态的任务不加入就绪队列
        // 将任务加入优先级队列中，如果时间片大于最小时间片，插入头部，否则插入尾部
        OsSchedTaskEnQueue(runTask);
    }

    // 从就绪队列获取一个优先级最高的task
    LosTaskCB *newTask = OsGetTopTask();
    g_losTask.newTask = newTask;

    // 如果 runtask 和 newtask 不同，则切换task的状态，
    // 把newtask的状态设为running， runTask 状态设为非running
    // isTaskSwitch设为True
    if (runTask != newTask) {
#if (LOSCFG_BASE_CORE_TSK_MONITOR == 1)
        OsTaskSwitchCheck();
#endif
        runTask->taskStatus &= ~OS_TASK_STATUS_RUNNING;
        newTask->taskStatus |= OS_TASK_STATUS_RUNNING;
        newTask->startTime = runTask->startTime;   // 新任务的开始时间设置为runtask的开始时间，在599行更新过
        isTaskSwitch = TRUE;

        OsHookCall(LOS_HOOK_TYPE_TASK_SWITCHEDIN);
    }

    // 如果newTask是就绪态，则将该任务从优先级队列删除，并取消就绪态
    OsSchedTaskDeQueue(newTask);

    // 计算newtask的运行结束时间，开始时间+时间片大小
    if (newTask->taskID != g_idleTaskID) {
        endTime = newTask->startTime + newTask->timeSlice;
    } else {
        endTime = OS_SCHED_MAX_RESPONSE_TIME - OS_TICK_RESPONSE_PRECISION;
    }

    // 如果g_schedResponseID == runTask->taskID，设置g_schedResponseTime为最大值
    if (g_schedResponseID == runTask->taskID) {
        g_schedResponseTime = OS_SCHED_MAX_RESPONSE_TIME;
    }
    // 设置newtask过期时间
    OsSchedSetNextExpireTime(newTask->taskID, endTime);

    return isTaskSwitch;
}

UINT64 LOS_SchedTickTimeoutNsGet(VOID)
{
    UINT32 intSave;
    UINT64 responseTime;
    UINT64 currTime;

    intSave = LOS_IntLock();
    responseTime = g_schedResponseTime;
    currTime = OsGetCurrSchedTimeCycle();
    LOS_IntRestore(intSave);

    if (responseTime > currTime) {
        responseTime = responseTime - currTime;
    } else {
        responseTime = 0; /* Tick interrupt already timeout */
    }

    return OS_SYS_CYCLE_TO_NS(responseTime, g_sysClock);
}

/**
 * @brief 时钟中断处理函数
 * 
 * @return VOID 
 */
VOID LOS_SchedTickHandler(VOID)
{   
    // 如果g_taskScheduled = Fasle，返回
    if (!g_taskScheduled) {
        return;
    }

    UINT32 intSave = LOS_IntLock();
    UINT64 tickStartTime = OsGetCurrSchedTimeCycle();
    if (g_schedResponseID == OS_INVALID) {
        g_tickIntLock++;
        if (g_swtmrScan != NULL) {
            // 调用软件timer的scan函数
            (VOID)g_swtmrScan();
        }
        // 检查sortlist，处理超时的任务
        (VOID)OsSchedScanTimerList();
        g_tickIntLock--;
    }

    // 更新runtask的时间片
    OsTimeSliceUpdate(g_losTask.runTask, tickStartTime);
    g_losTask.runTask->startTime = OsGetCurrSchedTimeCycle();

    g_schedResponseTime = OS_SCHED_MAX_RESPONSE_TIME;
    if (LOS_CHECK_SCHEDULE) {
        ArchTaskSchedule();
    } else {
        OsSchedUpdateExpireTime();
    }

    LOS_IntRestore(intSave);
}

VOID LOS_Schedule(VOID)
{
    if (g_taskScheduled && LOS_CHECK_SCHEDULE) {
        ArchTaskSchedule();
    }
}

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
