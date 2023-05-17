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

#include "los_membox.h"
#include "securec.h"
#include "los_interrupt.h"
#include "los_context.h"
#include "los_debug.h"
#include "los_task.h"


/* The magic length is 32 bits, the lower 8 bits are used to save the owner task ID,
   and the other 24 bits are used to set the magic number for verification. */
#define OS_MEMBOX_MAGIC         0xa55a5a00
#define OS_MEMBOX_TASKID_BITS   8
#define OS_MEMBOX_MAX_TASKID    ((1 << OS_MEMBOX_TASKID_BITS) - 1)
#define OS_MEMBOX_TASKID_GET(addr) (((UINTPTR)(addr)) & OS_MEMBOX_MAX_TASKID)

/**
 * @brief 设置node->pstNext指向一个magic数，magic数低8位存储taskID
 * 
 * @param node 
 * @return STATIC 
 */
STATIC INLINE VOID OsMemBoxSetMagic(LOS_MEMBOX_NODE *node)
{
    UINT8 taskID = (UINT8)LOS_CurTaskIDGet();
    // 设置node->pstNext指向一个magic数，magic数低8位存储taskID
    node->pstNext = (LOS_MEMBOX_NODE *)(OS_MEMBOX_MAGIC | taskID);
}

// 检查magic数
STATIC INLINE UINT32 OsMemBoxCheckMagic(LOS_MEMBOX_NODE *node)
{
    UINT32 taskID = OS_MEMBOX_TASKID_GET(node->pstNext);
    if (taskID > (LOSCFG_BASE_CORE_TSK_LIMIT + 1)) {
        return LOS_NOK;
    } else {
        return (node->pstNext == (LOS_MEMBOX_NODE *)(OS_MEMBOX_MAGIC | taskID)) ? LOS_OK : LOS_NOK;
    }
}

#define OS_MEMBOX_USER_ADDR(addr) \
    ((VOID *)((UINT8 *)(addr) + OS_MEMBOX_NODE_HEAD_SIZE))
#define OS_MEMBOX_NODE_ADDR(addr) \
    ((LOS_MEMBOX_NODE *)(VOID *)((UINT8 *)(addr) - OS_MEMBOX_NODE_HEAD_SIZE))
#define MEMBOX_LOCK(state)       ((state) = ArchIntLock())
#define MEMBOX_UNLOCK(state)     ArchIntRestore(state)

STATIC INLINE UINT32 OsCheckBoxMem(const LOS_MEMBOX_INFO *boxInfo, const VOID *node)
{
    UINT32 offset;

    if (boxInfo->uwBlkSize == 0) {
        return LOS_NOK;
    }

    // 计算内存块相对第一个内存块的偏移量
    offset = (UINT32)((UINTPTR)node - (UINTPTR)(boxInfo + 1));
    // 如果偏移量除以内存块大小的余数不为0，即是不是一整块
    if ((offset % boxInfo->uwBlkSize) != 0) {
        return LOS_NOK;
    }

    // 如果偏移量除以内存块大小的值>=块数，说明该内存块不在被内存池管理的区域内
    if ((offset / boxInfo->uwBlkSize) >= boxInfo->uwBlkNum) {
        return LOS_NOK;
    }

    // 检查magic数
    return OsMemBoxCheckMagic((LOS_MEMBOX_NODE *)node);
}

#if (LOSCFG_PLATFORM_EXC == 1)
STATIC LOS_MEMBOX_INFO *g_memBoxHead = NULL;
STATIC VOID OsMemBoxAdd(VOID *pool)
{
    LOS_MEMBOX_INFO *nextPool = g_memBoxHead;
    LOS_MEMBOX_INFO *curPool = NULL;

    while (nextPool != NULL) {
        curPool = nextPool;
        nextPool = nextPool->nextMemBox;
    }

    if (curPool == NULL) {
        g_memBoxHead = pool;
    } else {
        curPool->nextMemBox = pool;
    }

    ((LOS_MEMBOX_INFO *)pool)->nextMemBox = NULL;
}
#endif

/**
 * @brief 静态内存初始化
 * 
 * @param pool      内存池起始地址
 * @param poolSize  内存池大小
 * @param blkSize   内存块大小
 * @return UINT32 
 */
UINT32 LOS_MemboxInit(VOID *pool, UINT32 poolSize, UINT32 blkSize)
{
    LOS_MEMBOX_INFO *boxInfo = (LOS_MEMBOX_INFO *)pool;
    LOS_MEMBOX_NODE *node = NULL;
    UINT32 index;
    UINT32 intSave;

    if (pool == NULL) {
        return LOS_NOK;
    }

    if (blkSize == 0) {
        return LOS_NOK;
    }

    if (poolSize < sizeof(LOS_MEMBOX_INFO)) {
        return LOS_NOK;
    }

    MEMBOX_LOCK(intSave);
    // 内存块大小为 blkSize + LOS_MEMBOX_NODE结构体大小
    boxInfo->uwBlkSize = LOS_MEMBOX_ALIGNED(blkSize + OS_MEMBOX_NODE_HEAD_SIZE);
    // 计算内存块个数
    boxInfo->uwBlkNum = (poolSize - sizeof(LOS_MEMBOX_INFO)) / boxInfo->uwBlkSize;
    boxInfo->uwBlkCnt = 0;
    if (boxInfo->uwBlkNum == 0) {
        MEMBOX_UNLOCK(intSave);
        return LOS_NOK;
    }

    // 获取第一个内存块
    node = (LOS_MEMBOX_NODE *)(boxInfo + 1);

    boxInfo->stFreeList.pstNext = node;

    // 使用单链表串联起来
    for (index = 0; index < boxInfo->uwBlkNum - 1; ++index) {
        node->pstNext = OS_MEMBOX_NEXT(node, boxInfo->uwBlkSize);
        node = node->pstNext;
    }

    // 最后一个内存块
    node->pstNext = NULL;

#if (LOSCFG_PLATFORM_EXC == 1)
    OsMemBoxAdd(pool);
#endif

    MEMBOX_UNLOCK(intSave);

    return LOS_OK;
}

/**
 * @brief 从内存池中获取一个可用的内存块
 * 
 * @param pool 
 * @return VOID* 
 */
VOID *LOS_MemboxAlloc(VOID *pool)
{
    LOS_MEMBOX_INFO *boxInfo = (LOS_MEMBOX_INFO *)pool;
    LOS_MEMBOX_NODE *node = NULL;
    LOS_MEMBOX_NODE *nodeTmp = NULL;
    UINT32 intSave;

    if (pool == NULL) {
        return NULL;
    }

    MEMBOX_LOCK(intSave);
    node = &(boxInfo->stFreeList);
    if (node->pstNext != NULL) {
        // 获取下一个可用的内存块
        nodeTmp = node->pstNext;
        node->pstNext = nodeTmp->pstNext;
        // 设置node->pstNext指向一个magic数，magic数低8位存储taskID
        OsMemBoxSetMagic(nodeTmp);
        boxInfo->uwBlkCnt++;
    }
    MEMBOX_UNLOCK(intSave);

    // OS_MEMBOX_USER_ADDR(nodeTmp) 获取实际可用的内存块起始地址，即越过LOS_MEMBOX_NODE
    return (nodeTmp == NULL) ? NULL : OS_MEMBOX_USER_ADDR(nodeTmp);
}

UINT32 LOS_MemboxFree(VOID *pool, VOID *box)
{
    LOS_MEMBOX_INFO *boxInfo = (LOS_MEMBOX_INFO *)pool;
    UINT32 ret = LOS_NOK;
    UINT32 intSave;

    if ((pool == NULL) || (box == NULL)) {
        return LOS_NOK;
    }

    MEMBOX_LOCK(intSave);
    do {
        // 获取LOS_MEMBOX_NODE信息
        LOS_MEMBOX_NODE *node = OS_MEMBOX_NODE_ADDR(box);
        if (OsCheckBoxMem(boxInfo, node) != LOS_OK) {
            break;
        }
        // 头插法
        node->pstNext = boxInfo->stFreeList.pstNext;
        boxInfo->stFreeList.pstNext = node;
        boxInfo->uwBlkCnt--;
        ret = LOS_OK;
    } while (0);
    MEMBOX_UNLOCK(intSave);

    return ret;
}

/**
 * @brief 将内存块设为0值
 * 
 * @param pool 
 * @param box 
 * @return VOID 
 */
VOID LOS_MemboxClr(VOID *pool, VOID *box)
{
    LOS_MEMBOX_INFO *boxInfo = (LOS_MEMBOX_INFO *)pool;

    if ((pool == NULL) || (box == NULL)) {
        return;
    }

    (VOID)memset_s(box, (boxInfo->uwBlkSize - OS_MEMBOX_NODE_HEAD_SIZE), 0,
                   (boxInfo->uwBlkSize - OS_MEMBOX_NODE_HEAD_SIZE));
}

/**
 * @brief 展示当前内存池的属性，使用情况
 * 
 * @param pool 
 * @return VOID 
 */
VOID LOS_ShowBox(VOID *pool)
{
    UINT32 index;
    UINT32 intSave;
    LOS_MEMBOX_INFO *boxInfo = (LOS_MEMBOX_INFO *)pool;
    LOS_MEMBOX_NODE *node = NULL;

    if (pool == NULL) {
        return;
    }
    MEMBOX_LOCK(intSave);
    PRINT_INFO("membox(%p, 0x%x, 0x%x):\r\n", pool, boxInfo->uwBlkSize, boxInfo->uwBlkNum);
    PRINT_INFO("free node list:\r\n");

    for (node = boxInfo->stFreeList.pstNext, index = 0; node != NULL;
        node = node->pstNext, ++index) {
        PRINT_INFO("(%u, %p)\r\n", index, node);
    }

    PRINT_INFO("all node list:\r\n");
    node = (LOS_MEMBOX_NODE *)(boxInfo + 1);
    for (index = 0; index < boxInfo->uwBlkNum; ++index, node = OS_MEMBOX_NEXT(node, boxInfo->uwBlkSize)) {
        PRINT_INFO("(%u, %p, %p)\r\n", index, node, node->pstNext);
    }
    MEMBOX_UNLOCK(intSave);
}

/**
 * @brief 获得内存池属性（LOS_MEMBOX_INFO）
 * 
 * @param boxMem 
 * @param maxBlk 
 * @param blkCnt 
 * @param blkSize 
 * @return UINT32 
 */
UINT32 LOS_MemboxStatisticsGet(const VOID *boxMem, UINT32 *maxBlk,
                               UINT32 *blkCnt, UINT32 *blkSize)
{
    if ((boxMem == NULL) || (maxBlk == NULL) || (blkCnt == NULL) || (blkSize == NULL)) {
        return LOS_NOK;
    }

    *maxBlk = ((OS_MEMBOX_S *)boxMem)->uwBlkNum;
    *blkCnt = ((OS_MEMBOX_S *)boxMem)->uwBlkCnt;
    *blkSize = ((OS_MEMBOX_S *)boxMem)->uwBlkSize;

    return LOS_OK;
}

#if (LOSCFG_PLATFORM_EXC == 1)
STATIC VOID OsMemboxExcInfoGetSub(const LOS_MEMBOX_INFO *pool, MemInfoCB *memExcInfo)
{
    LOS_MEMBOX_NODE *node = NULL;
    UINTPTR poolStart, poolEnd;
    UINT32 index;
    UINT32 intSave;

    (VOID)memset_s(memExcInfo, sizeof(MemInfoCB), 0, sizeof(MemInfoCB));

    MEMBOX_LOCK(intSave);
    memExcInfo->type = MEM_MANG_MEMBOX;
    memExcInfo->startAddr = (UINTPTR)pool;
    memExcInfo->blockSize = pool->uwBlkSize;
    memExcInfo->size = pool->uwBlkNum; /* Block num */
    memExcInfo->free = pool->uwBlkNum - pool->uwBlkCnt;

    poolStart = (UINTPTR)pool;
    poolEnd = poolStart + pool->uwBlkSize * pool->uwBlkNum + sizeof(LOS_MEMBOX_INFO);
    node = (LOS_MEMBOX_NODE *)(pool + 1);
    for (index = 0; index < pool->uwBlkNum; ++index, node = OS_MEMBOX_NEXT(node, pool->uwBlkSize)) {
        if (((UINTPTR)node < poolStart) || ((UINTPTR)node >= poolEnd)) {
            if (OsMemBoxCheckMagic(node)) {
                memExcInfo->errorAddr = (UINT32)(UINTPTR)((CHAR *)node + OS_MEMBOX_NODE_HEAD_SIZE);
                memExcInfo->errorLen = pool->uwBlkSize - OS_MEMBOX_NODE_HEAD_SIZE;
                memExcInfo->errorOwner = OS_MEMBOX_TASKID_GET(node->pstNext);
                break;
            }
        }
    }
    MEMBOX_UNLOCK(intSave);
}

UINT32 OsMemboxExcInfoGet(UINT32 memNumMax, MemInfoCB *memExcInfo)
{
    LOS_MEMBOX_INFO *memBox = g_memBoxHead;
    UINT32 count = 0;
    UINT8 *buffer = (UINT8 *)memExcInfo;

    while (memBox != NULL) {
        OsMemboxExcInfoGetSub(memBox, (MemInfoCB *)buffer);
        count++;
        buffer += sizeof(MemInfoCB);
        if (count >= memNumMax) {
            break;
        }
        memBox = memBox->nextMemBox;
    }

    return count;
}
#endif

