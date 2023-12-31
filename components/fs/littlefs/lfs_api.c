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

#define _GNU_SOURCE 1
#include "lfs_api.h"
#include "los_config.h"
#include "los_mux.h"
#include "los_debug.h"
#include "securec.h"

lfs_t g_lfs;
FileDirInfo g_lfsDir[LFS_MAX_OPEN_DIRS] = {0};

struct FileOpInfo g_fsOp[LOSCFG_LFS_MAX_MOUNT_SIZE] = {0};
static LittleFsHandleStruct g_handle[LOSCFG_LFS_MAX_OPEN_FILES] = {0};
struct dirent g_nameValue;
static const char *g_littlefsMntName[LOSCFG_LFS_MAX_MOUNT_SIZE] = {"/a", "/littlefs"};
#define LFS_MUTEX_UNINIT (-1)
static UINT32 g_lfsMutex = LFS_MUTEX_UNINIT;

static int LfsLock(void)
{
    if (LOS_MuxPend(g_lfsMutex, LOS_WAIT_FOREVER) != LOS_OK) {
        PRINT_ERR("LfsLock failed!");
        return LOS_NOK;
    }

    return LOS_OK;
}

static void LfsUnlock(void)
{
    (void)LOS_MuxPost(g_lfsMutex);
}

LittleFsHandleStruct *LfsAllocFd(const char *fileName, int *fd)
{
    for (int i = 0; i < LOSCFG_LFS_MAX_OPEN_FILES; i++) {
        if (g_handle[i].useFlag == 0) {
            *fd = i;
            g_handle[i].useFlag = 1;
            g_handle[i].pathName = strdup(fileName);
            return &(g_handle[i]);
        }
    }
    *fd = INVALID_FD;
    return NULL;
}

static void LfsFreeFd(int fd)
{
    g_handle[fd].useFlag = 0;
    if (g_handle[fd].pathName != NULL) {
        free((void *)g_handle[fd].pathName);
        g_handle[fd].pathName = NULL;
    }

    if (g_handle[fd].lfsHandle != NULL) {
        g_handle[fd].lfsHandle = NULL;
    }
}

BOOL CheckFileIsOpen(const char *fileName)
{
    for (int i = 0; i < LOSCFG_LFS_MAX_OPEN_FILES; i++) {
        if (g_handle[i].useFlag == 1) {
            if (strcmp(g_handle[i].pathName, fileName) == 0) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

static BOOL LfsFdIsValid(int fd)
{
    if (fd >= LOSCFG_LFS_MAX_OPEN_FILES || fd < 0) {
        return FALSE;
    }
    if (g_handle[fd].lfsHandle == NULL) {
        return FALSE;
    }
    return TRUE;
}

FileDirInfo *GetFreeDir(const char *dirName)
{
    for (int i = 0; i < LFS_MAX_OPEN_DIRS; i++) {
        if (g_lfsDir[i].useFlag == 0) {
            g_lfsDir[i].useFlag = 1;
            g_lfsDir[i].dirName = strdup(dirName);
            return &(g_lfsDir[i]);
        }
    }
    return NULL;
}

void FreeDirInfo(const char *dirName)
{
    for (int i = 0; i < LFS_MAX_OPEN_DIRS; i++) {
        if (g_lfsDir[i].useFlag == 1 && strcmp(g_lfsDir[i].dirName, dirName) == 0) {
            g_lfsDir[i].useFlag = 0;
            if (g_lfsDir[i].dirName) {
                free(g_lfsDir[i].dirName);
                g_lfsDir[i].dirName = NULL;
            }
        }
    }
}

BOOL CheckDirIsOpen(const char *dirName)
{
    for (int i = 0; i < LFS_MAX_OPEN_DIRS; i++) {
        if (g_lfsDir[i].useFlag == 1) {
            if (strcmp(g_lfsDir[i].dirName, dirName) == 0) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

int GetFirstLevelPathLen(const char *pathName)
{
    int len = 1;
    for (int i = 1; i < strlen(pathName) + 1; i++) {
        if (pathName[i] == '/') {
            break;
        }
        len++;
    }

    return len;
}

BOOL CheckPathIsMounted(const char *pathName, struct FileOpInfo **fileOpInfo)
{
    char tmpName[LITTLEFS_MAX_LFN_LEN] = {0};
    int len = GetFirstLevelPathLen(pathName);

    for (int i = 0; i < LOSCFG_LFS_MAX_MOUNT_SIZE; i++) {
        if (g_fsOp[i].useFlag == 1) {
            (void)strncpy_s(tmpName, LITTLEFS_MAX_LFN_LEN, pathName, len);
            if (strcmp(tmpName, g_fsOp[i].dirName) == 0) {
                *fileOpInfo = &(g_fsOp[i]);
                return TRUE;
            }
        }
    }
    return FALSE;
}

struct FileOpInfo *AllocMountRes(const char* target, const struct FileOps *fileOps)
{
    for (int i = 0; i < LOSCFG_LFS_MAX_MOUNT_SIZE; i++) {
        if (g_fsOp[i].useFlag == 0 && strcmp(target, g_littlefsMntName[i]) == 0) {
            g_fsOp[i].useFlag = 1;
            g_fsOp[i].fsVops = fileOps;
            g_fsOp[i].dirName = strdup(target);
            return &(g_fsOp[i]);
        }
    }

    return NULL;
}

int SetDefaultMountPath(int pathNameIndex, const char* target)
{
    if (pathNameIndex >= LOSCFG_LFS_MAX_MOUNT_SIZE) {
        return VFS_ERROR;
    }

    g_littlefsMntName[pathNameIndex] = strdup(target);
    return VFS_OK;
}

struct FileOpInfo *GetMountRes(const char *target, int *mountIndex)
{
    for (int i = 0; i < LOSCFG_LFS_MAX_MOUNT_SIZE; i++) {
        if (g_fsOp[i].useFlag == 1) {
            if (g_fsOp[i].dirName && strcmp(target, g_fsOp[i].dirName) == 0) {
                *mountIndex = i;
                return &(g_fsOp[i]);
            }
        }
    }

    return NULL;
}

int FreeMountResByIndex(int mountIndex)
{
    if (mountIndex < 0 || mountIndex >= LOSCFG_LFS_MAX_MOUNT_SIZE) {
        return VFS_ERROR;
    }

    if (g_fsOp[mountIndex].useFlag == 1 && g_fsOp[mountIndex].dirName != NULL) {
        g_fsOp[mountIndex].useFlag = 0;
        free(g_fsOp[mountIndex].dirName);
        g_fsOp[mountIndex].dirName = NULL;
    }

    return VFS_OK;
}

int FreeMountRes(const char *target)
{
    for (int i = 0; i < LOSCFG_LFS_MAX_MOUNT_SIZE; i++) {
        if (g_fsOp[i].useFlag == 1) {
            if (g_fsOp[i].dirName && strcmp(target, g_fsOp[i].dirName) == 0) {
                g_fsOp[i].useFlag = 0;
                free(g_fsOp[i].dirName);
                g_fsOp[i].dirName = NULL;
                return VFS_OK;
            }
        }
    }

    return VFS_ERROR;
}

static int ConvertFlagToLfsOpenFlag (int oflags)
{
    int lfsOpenFlag = 0;

    if (oflags & O_CREAT) {
        lfsOpenFlag |= LFS_O_CREAT;
    }

    if (oflags & O_EXCL) {
        lfsOpenFlag |= LFS_O_EXCL;
    }

    if (oflags & O_TRUNC) {
        lfsOpenFlag |= LFS_O_TRUNC;
    }

    if (oflags & O_APPEND) {
        lfsOpenFlag |= LFS_O_APPEND;
    }

    if (oflags & O_RDWR) {
        lfsOpenFlag |= LFS_O_RDWR;
    }

    if (oflags & O_WRONLY) {
        lfsOpenFlag |= LFS_O_WRONLY;
    }

    if (oflags == O_RDONLY) {
        lfsOpenFlag |= LFS_O_RDONLY;
    }

    return lfsOpenFlag;
}

static int LittlefsErrno(int result)
{
    return (result < 0) ? -result : result;
}

const struct MountOps g_lfsMnt = {
    .Mount = LfsMount,
    .Umount = LfsUmount,
};

const struct FileOps g_lfsFops = {
    .Mkdir = LfsMkdir,
    .Unlink = LfsUnlink,
    .Rmdir = LfsRmdir,
    .Opendir = LfsOpendir,
    .Readdir = LfsReaddir,
    .Closedir = LfsClosedir,
    .Open = LfsOpen,
    .Close = LfsClose,
    .Write = LfsWrite,
    .Read = LfsRead,
    .Seek = LfsSeek,
    .Rename = LfsRename,
    .Getattr = LfsStat,
    .Fsync = LfsFsync,
    .Fstat = LfsFstat,
    .Pread = LfsPread,
    .Pwrite = LfsPwrite,
};

int LfsMount(const char *source, const char *target, const char *fileSystemType, unsigned long mountflags,
    const void *data)
{
    int ret;
    struct FileOpInfo *fileOpInfo = NULL;

    if (target == NULL || fileSystemType == NULL || data == NULL) {
        errno = EFAULT;
        return VFS_ERROR;
    }

    if (strcmp(fileSystemType, "littlefs") != 0) {
        errno = ENODEV;
        return VFS_ERROR;
    }

    if (g_lfsMutex == LFS_MUTEX_UNINIT) {
        if (LOS_MuxCreate(&g_lfsMutex) != LOS_OK) {
            errno = EBUSY;
            return VFS_ERROR;
        }
    }

    if (LfsLock() != LOS_OK) {
        errno = EAGAIN;
        return VFS_ERROR;
    }

    if (CheckPathIsMounted(target, &fileOpInfo)) {
        errno = EBUSY;
        ret = VFS_ERROR;
        goto ERROUT;
    }

    // select free mount resource
    fileOpInfo = AllocMountRes(target, &g_lfsFops);
    if (fileOpInfo == NULL) {
        errno = ENODEV;
        ret = VFS_ERROR;
        goto ERROUT;
    }

    ret = lfs_mount(&(fileOpInfo->lfsInfo), (struct lfs_config*)data);
    if (ret != 0) {
        ret = lfs_format(&(fileOpInfo->lfsInfo), (struct lfs_config*)data);
        if (ret == 0) {
            ret = lfs_mount(&(fileOpInfo->lfsInfo), (struct lfs_config*)data);
        }
    }

    if (ret != 0) {
        errno = LittlefsErrno(ret);
        ret = VFS_ERROR;
    }

ERROUT:
    LfsUnlock();
    return ret;
}

int LfsUmount(const char *target)
{
    int ret;
    int mountIndex = -1;
    struct FileOpInfo *fileOpInfo = NULL;

    if (target == NULL) {
        errno = EFAULT;
        return VFS_ERROR;
    }

    if (LfsLock() != LOS_OK) {
        errno = EAGAIN;
        return VFS_ERROR;
    }

    fileOpInfo = GetMountRes(target, &mountIndex);
    if (fileOpInfo == NULL) {
        errno = ENOENT;
        LfsUnlock();
        return VFS_ERROR;
    }

    ret = lfs_unmount(&(fileOpInfo->lfsInfo));
    if (ret != 0) {
        errno = LittlefsErrno(ret);
        ret = VFS_ERROR;
    }

    (void)FreeMountResByIndex(mountIndex);
    LfsUnlock();
    return ret;
}

int LfsUnlink(const char *fileName)
{
    int ret;
    struct FileOpInfo *fileOpInfo = NULL;

    if (fileName == NULL) {
        errno = EFAULT;
        return VFS_ERROR;
    }

    if (LfsLock() != LOS_OK) {
        errno = EAGAIN;
        return VFS_ERROR;
    }

    if (CheckPathIsMounted(fileName, &fileOpInfo) == FALSE || fileOpInfo == NULL) {
        errno = ENOENT;
        LfsUnlock();
        return VFS_ERROR;
    }

    ret = lfs_remove(&(fileOpInfo->lfsInfo), fileName);
    if (ret != 0) {
        errno = LittlefsErrno(ret);
        ret = VFS_ERROR;
    }

    LfsUnlock();
    return ret;
}

int LfsMkdir(const char *dirName, mode_t mode)
{
    int ret;
    struct FileOpInfo *fileOpInfo = NULL;

    if (dirName == NULL) {
        errno = EFAULT;
        return VFS_ERROR;
    }

    if (LfsLock() != LOS_OK) {
        errno = EAGAIN;
        return VFS_ERROR;
    }

    if (CheckPathIsMounted(dirName, &fileOpInfo) == FALSE || fileOpInfo == NULL) {
        errno = ENOENT;
        LfsUnlock();
        return VFS_ERROR;
    }

    ret = lfs_mkdir(&(fileOpInfo->lfsInfo), dirName);
    if (ret != 0) {
        errno = LittlefsErrno(ret);
        ret = VFS_ERROR;
    }

    LfsUnlock();
    return ret;
}

int LfsRmdir(const char *dirName)
{
    int ret;

    struct FileOpInfo *fileOpInfo = NULL;

    if (dirName == NULL) {
        errno = EFAULT;
        return VFS_ERROR;
    }

    if (LfsLock() != LOS_OK) {
        errno = EAGAIN;
        return VFS_ERROR;
    }

    if (CheckPathIsMounted(dirName, &fileOpInfo) == FALSE || fileOpInfo == NULL) {
        errno = ENOENT;
        LfsUnlock();
        return VFS_ERROR;
    }

    ret = lfs_remove(&(fileOpInfo->lfsInfo), dirName);
    if (ret != 0) {
        errno = LittlefsErrno(ret);
        ret = VFS_ERROR;
    }

    LfsUnlock();
    return ret;
}

DIR *LfsOpendir(const char *dirName)
{
    int ret;
    struct FileOpInfo *fileOpInfo = NULL;

    if (dirName == NULL) {
        errno = EFAULT;
        return NULL;
    }

    if (LfsLock() != LOS_OK) {
        errno = EAGAIN;
        return NULL;
    }

    if (CheckPathIsMounted(dirName, &fileOpInfo) == FALSE || fileOpInfo == NULL) {
        errno = ENOENT;
        goto ERROUT;
    }

    if (CheckDirIsOpen(dirName)) {
        errno = EBUSY;
        goto ERROUT;
    }

    FileDirInfo *dirInfo = GetFreeDir(dirName);
    if (dirInfo == NULL) {
        errno = ENFILE;
        goto ERROUT;
    }

    ret = lfs_dir_open(&(fileOpInfo->lfsInfo), (lfs_dir_t *)(&(dirInfo->dir)), dirName);

    if (ret != 0) {
        FreeDirInfo(dirName);
        errno = LittlefsErrno(ret);
        goto ERROUT;
    }

    dirInfo->lfsHandle = &(fileOpInfo->lfsInfo);

    LfsUnlock();
    return (DIR *)dirInfo;

ERROUT:
    LfsUnlock();
    return NULL;
}

struct dirent *LfsReaddir(DIR *dir)
{
    int ret;
    struct lfs_info lfsInfo;

    FileDirInfo *dirInfo = (FileDirInfo *)dir;

    if (dirInfo == NULL || dirInfo->lfsHandle == NULL) {
        errno = EBADF;
        return NULL;
    }

    if (LfsLock() != LOS_OK) {
        errno = EAGAIN;
        return NULL;
    }

    ret = lfs_dir_read(dirInfo->lfsHandle, (lfs_dir_t *)(&(dirInfo->dir)), &lfsInfo);
    if (ret == TRUE) {
        (void)strncpy_s(g_nameValue.d_name, sizeof(g_nameValue.d_name), lfsInfo.name, strlen(lfsInfo.name) + 1);
        if (lfsInfo.type == LFS_TYPE_DIR) {
            g_nameValue.d_type = DT_DIR;
        } else if (lfsInfo.type == LFS_TYPE_REG) {
            g_nameValue.d_type = DT_REG;
        }

        g_nameValue.d_reclen = lfsInfo.size;

        LfsUnlock();
        return &g_nameValue;
    }

    if (ret != 0) {
        errno = LittlefsErrno(ret);
    }

    LfsUnlock();
    return NULL;
}

int LfsClosedir(DIR *dir)
{
    int ret;
    FileDirInfo *dirInfo = (FileDirInfo *)dir;

    if (dirInfo == NULL || dirInfo->lfsHandle == NULL) {
        errno = EBADF;
        return VFS_ERROR;
    }

    if (LfsLock() != LOS_OK) {
        errno = EAGAIN;
        return VFS_ERROR;
    }

    ret = lfs_dir_close(dirInfo->lfsHandle, (lfs_dir_t *)(&(dirInfo->dir)));

    FreeDirInfo(dirInfo->dirName);

    if (ret != 0) {
        errno = LittlefsErrno(ret);
        ret = VFS_ERROR;
    }

    LfsUnlock();
    return ret;
}

int LfsOpen(const char *pathName, int openFlag, ...)
{
    int fd = INVALID_FD;
    int err = INVALID_FD;

    struct FileOpInfo *fileOpInfo = NULL;

    if (pathName == NULL) {
        errno = EFAULT;
        return INVALID_FD;
    }

    if (LfsLock() != LOS_OK) {
        errno = EAGAIN;
        return VFS_ERROR;
    }

    if (CheckPathIsMounted(pathName, &fileOpInfo) == FALSE || fileOpInfo == NULL) {
        errno = ENOENT;
        goto ERROUT;
    }
    // if file is already open, return invalid fd
    if (CheckFileIsOpen(pathName)) {
        errno = EBUSY;
        goto ERROUT;
    }

    LittleFsHandleStruct *fsHandle = LfsAllocFd(pathName, &fd);
    if (fd == INVALID_FD) {
        errno = ENFILE;
        goto ERROUT;
    }

    int lfsOpenFlag = ConvertFlagToLfsOpenFlag(openFlag);
    err = lfs_file_open(&(fileOpInfo->lfsInfo), &(fsHandle->file), pathName, lfsOpenFlag);
    if (err != 0) {
        LfsFreeFd(fd);
        errno = LittlefsErrno(err);
        goto ERROUT;
    }

    g_handle[fd].lfsHandle = &(fileOpInfo->lfsInfo);
    LfsUnlock();
    return fd;

ERROUT:
    LfsUnlock();
    return INVALID_FD;
}

int LfsRead(int fd, void *buf, unsigned int len)
{
    int ret;

    if (buf == NULL) {
        errno = EFAULT;
        return VFS_ERROR;
    }

    if (LfsLock() != LOS_OK) {
        errno = EAGAIN;
        return VFS_ERROR;
    }

    if (LfsFdIsValid(fd) == FALSE) {
        errno = EBADF;
        LfsUnlock();
        return VFS_ERROR;
    }

    ret = lfs_file_read(g_handle[fd].lfsHandle, &(g_handle[fd].file), buf, len);
    if (ret < 0) {
        errno = LittlefsErrno(ret);
        ret = VFS_ERROR;
    }
    LfsUnlock();
    return ret;
}

int LfsWrite(int fd, const void *buf, unsigned int len)
{
    int ret;

    if (buf == NULL) {
        errno = EFAULT;
        return VFS_ERROR;
    }

    if (LfsLock() != LOS_OK) {
        errno = EAGAIN;
        return VFS_ERROR;
    }

    if (LfsFdIsValid(fd) == FALSE) {
        errno = EBADF;
        LfsUnlock();
        return VFS_ERROR;
    }

    ret = lfs_file_write(g_handle[fd].lfsHandle, &(g_handle[fd].file), buf, len);
    if (ret < 0) {
        errno = LittlefsErrno(ret);
        ret = VFS_ERROR;
    }
    LfsUnlock();
    return ret;
}

off_t LfsSeek(int fd, off_t offset, int whence)
{
    off_t ret;

    if (LfsLock() != LOS_OK) {
        errno = EAGAIN;
        return VFS_ERROR;
    }

    if (LfsFdIsValid(fd) == FALSE) {
        errno = EBADF;
        LfsUnlock();
        return VFS_ERROR;
    }

    ret = (off_t)lfs_file_seek(g_handle[fd].lfsHandle, &(g_handle[fd].file), offset, whence);
    if (ret < 0) {
        errno = LittlefsErrno(ret);
        ret = VFS_ERROR;
    }

    LfsUnlock();
    return ret;
}

int LfsClose(int fd)
{
    int ret;

    if (LfsLock() != LOS_OK) {
        errno = EAGAIN;
        return VFS_ERROR;
    }

    if (LfsFdIsValid(fd) == FALSE) {
        errno = EBADF;
        LfsUnlock();
        return VFS_ERROR;
    }

    ret = lfs_file_close(g_handle[fd].lfsHandle, &(g_handle[fd].file));

    LfsFreeFd(fd);

    if (ret != 0) {
        errno = LittlefsErrno(ret);
        ret = VFS_ERROR;
    }

    LfsUnlock();
    return ret;
}

int LfsRename(const char *oldName, const char *newName)
{
    int ret;
    struct FileOpInfo *fileOpInfo = NULL;

    if (oldName == NULL || newName == NULL) {
        errno = EFAULT;
        return VFS_ERROR;
    }

    if (LfsLock() != LOS_OK) {
        errno = EAGAIN;
        return VFS_ERROR;
    }

    if (CheckPathIsMounted(oldName, &fileOpInfo) == FALSE || fileOpInfo == NULL) {
        errno = ENOENT;
        LfsUnlock();
        return VFS_ERROR;
    }

    ret = lfs_rename(&(fileOpInfo->lfsInfo), oldName, newName);
    if (ret != 0) {
        errno = LittlefsErrno(ret);
        ret = VFS_ERROR;
    }

    LfsUnlock();
    return ret;
}

int LfsStat(const char *path, struct stat *buf)
{
    int ret;
    struct lfs_info info;
    struct FileOpInfo *fileOpInfo = NULL;

    if (path == NULL || buf == NULL) {
        errno = EFAULT;
        return VFS_ERROR;
    }

    if (LfsLock() != LOS_OK) {
        errno = EAGAIN;
        return VFS_ERROR;
    }

    if (CheckPathIsMounted(path, &fileOpInfo) == FALSE || fileOpInfo == NULL) {
        errno = ENOENT;
        LfsUnlock();
        return VFS_ERROR;
    }

    ret = lfs_stat(&(fileOpInfo->lfsInfo), path, &info);
    if (ret == 0) {
        buf->st_size = info.size;
        if (info.type == LFS_TYPE_REG) {
            buf->st_mode = S_IFREG;
        } else {
            buf->st_mode = S_IFDIR;
        }
    } else {
        errno = LittlefsErrno(ret);
        ret = VFS_ERROR;
    }

    LfsUnlock();
    return ret;
}

int LfsFsync(int fd)
{
    int ret;

    if (LfsLock() != LOS_OK) {
        errno = EAGAIN;
        return VFS_ERROR;
    }

    if (LfsFdIsValid(fd) == FALSE) {
        errno = EBADF;
        LfsUnlock();
        return VFS_ERROR;
    }

    ret = lfs_file_sync(g_handle[fd].lfsHandle, &(g_handle[fd].file));
    if (ret != 0) {
        errno = LittlefsErrno(ret);
        ret = VFS_ERROR;
    }
    LfsUnlock();
    return ret;
}

int LfsFstat(int fd, struct stat *buf)
{
    int ret;
    struct lfs_info info;

    if (buf == NULL) {
        errno = EFAULT;
        return FS_FAILURE;
    }

    if (LfsLock() != LOS_OK) {
        errno = EAGAIN;
        return VFS_ERROR;
    }

    if (LfsFdIsValid(fd) == FALSE) {
        errno = EBADF;
        LfsUnlock();
        return VFS_ERROR;
    }

    ret = lfs_stat(g_handle[fd].lfsHandle, g_handle[fd].pathName, &info);
    if (ret == 0) {
        buf->st_size = info.size;
        if (info.type == LFS_TYPE_REG) {
            buf->st_mode = S_IFREG;
        } else {
            buf->st_mode = S_IFDIR;
        }
    } else {
        errno = LittlefsErrno(ret);
        ret = VFS_ERROR;
    }
    LfsUnlock();
    return ret;
}

int LfsPread(int fd, void *buf, size_t nbyte, off_t offset)
{
    int ret;
    off_t savepos, pos;

    if (buf == NULL) {
        errno = EFAULT;
        return VFS_ERROR;
    }

    if (LfsLock() != LOS_OK) {
        errno = EAGAIN;
        return VFS_ERROR;
    }

    if (LfsFdIsValid(fd) == FALSE) {
        errno = EBADF;
        LfsUnlock();
        return VFS_ERROR;
    }

    savepos = (off_t)lfs_file_seek(g_handle[fd].lfsHandle, &(g_handle[fd].file), 0, SEEK_CUR);
    if (savepos == (off_t)-1) {
        errno = LittlefsErrno(savepos);
        LfsUnlock();
        return VFS_ERROR;
    }

    pos = (off_t)lfs_file_seek(g_handle[fd].lfsHandle, &(g_handle[fd].file), offset, SEEK_SET);
    if (pos == (off_t)-1) {
        errno = LittlefsErrno(pos);
        LfsUnlock();
        return VFS_ERROR;
    }

    ret = lfs_file_read(g_handle[fd].lfsHandle, &(g_handle[fd].file), buf, nbyte);
    if (ret < 0) {
        errno = LittlefsErrno(ret);
        ret = VFS_ERROR;
    }

    pos = (off_t)lfs_file_seek(g_handle[fd].lfsHandle, &(g_handle[fd].file), savepos, SEEK_SET);
    if ((pos == (off_t)-1) && (ret >= 0)) {
        errno = LittlefsErrno(pos);
        ret = VFS_ERROR;
    }

    LfsUnlock();
    return ret;
}

int LfsPwrite(int fd, const void *buf, size_t nbyte, off_t offset)
{
    int ret;
    off_t savepos, pos;

    if (buf == NULL) {
        errno = EFAULT;
        return VFS_ERROR;
    }

    if (LfsLock() != LOS_OK) {
        errno = EAGAIN;
        return VFS_ERROR;
    }

    if (LfsFdIsValid(fd) == FALSE) {
        errno = EBADF;
        LfsUnlock();
        return VFS_ERROR;
    }

    savepos = (off_t)lfs_file_seek(g_handle[fd].lfsHandle, &(g_handle[fd].file), 0, SEEK_CUR);
    if (savepos == (off_t)-1) {
        errno = LittlefsErrno(savepos);
        LfsUnlock();
        return VFS_ERROR;
    }

    pos = (off_t)lfs_file_seek(g_handle[fd].lfsHandle, &(g_handle[fd].file), offset, SEEK_SET);
    if (pos == (off_t)-1) {
        errno = LittlefsErrno(pos);
        LfsUnlock();
        return VFS_ERROR;
    }

    ret = lfs_file_write(g_handle[fd].lfsHandle, &(g_handle[fd].file), buf, nbyte);
    if (ret < 0) {
        errno = LittlefsErrno(ret);
        ret = VFS_ERROR;
    }

    pos = (off_t)lfs_file_seek(g_handle[fd].lfsHandle, &(g_handle[fd].file), savepos, SEEK_SET);
    if ((pos == (off_t)-1) && (ret >= 0)) {
        errno = LittlefsErrno(pos);
        ret = VFS_ERROR;
    }

    LfsUnlock();
    return ret;
}
