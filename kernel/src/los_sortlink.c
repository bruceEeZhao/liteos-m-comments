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

#include "los_sortlink.h"
#include "los_sched.h"
#include "los_debug.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

SortLinkAttribute g_taskSortLink;
SortLinkAttribute g_swtmrSortLink;

UINT32 OsSortLinkInit(SortLinkAttribute *sortLinkHeader)
{
    LOS_ListInit(&sortLinkHeader->sortLink);
    return LOS_OK;
}

/// @brief 按responseTime大小顺序插入链表，head->next 是最小的
/// @param sortLinkHeader 
/// @param sortList 
/// @return 
STATIC INLINE VOID OsAddNode2SortLink(SortLinkAttribute *sortLinkHeader, SortLinkList *sortList)
{
    LOS_DL_LIST *head = (LOS_DL_LIST *)&sortLinkHeader->sortLink;

    if (LOS_ListEmpty(head)) {
        LOS_ListAdd(head, &sortList->sortLinkNode);
        return;
    }

    SortLinkList *listSorted = LOS_DL_LIST_ENTRY(head->pstNext, SortLinkList, sortLinkNode);
    if (listSorted->responseTime > sortList->responseTime) {
        LOS_ListAdd(head, &sortList->sortLinkNode);
        return;
    } else if (listSorted->responseTime == sortList->responseTime) {
        LOS_ListAdd(head->pstNext, &sortList->sortLinkNode);
        return;
    }

    LOS_DL_LIST *prevNode = head->pstPrev;
    do {
        listSorted = LOS_DL_LIST_ENTRY(prevNode, SortLinkList, sortLinkNode);
        if (listSorted->responseTime <= sortList->responseTime) {
            LOS_ListAdd(prevNode, &sortList->sortLinkNode);
            break;
        }

        prevNode = prevNode->pstPrev;
    } while (1);
}

/// @brief 计算node 的 responseTime, 按responseTime大小顺序插入有序链表，head->next 是最小的
/// @param node 
/// @param startTime 
/// @param waitTicks 
/// @param type 
/// @return 
VOID OsAdd2SortLink(SortLinkList *node, UINT64 startTime, UINT32 waitTicks, SortLinkType type)
{
    UINT32 intSave;
    SortLinkAttribute *sortLinkHeader = NULL;

    if (type == OS_SORT_LINK_TASK) {
        sortLinkHeader = &g_taskSortLink;
    } else if (type == OS_SORT_LINK_SWTMR) {
        sortLinkHeader = &g_swtmrSortLink;
    } else {
        LOS_Panic("Sort link type error : %u\n", type);
    }

    intSave = LOS_IntLock();
    // 计算node 的 responseTime，responseTime = (startTime + (((UINT64)(waitTicks) * g_sysClock) / 1000)))
    SET_SORTLIST_VALUE(node, startTime + OS_SYS_TICK_TO_CYCLE(waitTicks));
    // 按responseTime大小顺序插入链表，head->next 是最小的
    OsAddNode2SortLink(sortLinkHeader, node);
    LOS_IntRestore(intSave);
}

/**
 * @brief 将节点从sortlist中删除
 * 
 * @param node 
 * @return VOID 
 */
VOID OsDeleteSortLink(SortLinkList *node)
{
    UINT32 intSave;

    intSave = LOS_IntLock();
    if (node->responseTime != OS_SORT_LINK_INVALID_TIME) {
        OsSchedResetSchedResponseTime(node->responseTime);
        OsDeleteNodeSortLink(node);
    }
    LOS_IntRestore(intSave);
}

/**
 * @brief 根据type获取sortlist
 * 
 * @param type 
 * @return SortLinkAttribute* 
 */
SortLinkAttribute *OsGetSortLinkAttribute(SortLinkType type)
{
    if (type == OS_SORT_LINK_TASK) {
        return &g_taskSortLink;
    } else if (type == OS_SORT_LINK_SWTMR) {
        return &g_swtmrSortLink;
    }

    PRINT_ERR("Invalid sort link type!\n");
    return NULL;
}

UINT64 OsSortLinkGetTargetExpireTime(UINT64 currTime, const SortLinkList *targetSortList)
{
    if (currTime >= targetSortList->responseTime) {
        return 0;
    }

    return (targetSortList->responseTime - currTime);
}

UINT64 OsSortLinkGetNextExpireTime(const SortLinkAttribute *sortLinkHeader)
{
    LOS_DL_LIST *head = (LOS_DL_LIST *)&sortLinkHeader->sortLink;

    if (LOS_ListEmpty(head)) {
        return 0;
    }

    SortLinkList *listSorted = LOS_DL_LIST_ENTRY(head->pstNext, SortLinkList, sortLinkNode);
    return OsSortLinkGetTargetExpireTime(OsGetCurrSchedTimeCycle(), listSorted);
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */
