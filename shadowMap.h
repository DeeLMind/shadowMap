#ifndef _SHADOW_MAP_H
#define _SHADOW_MAP_H


/**
 * 安装hook
 */
BOOL WINAPI shadowMap_InstallHook(HMODULE hModule);

/**
* 卸载Hook
*/
BOOL WINAPI shadowMap_UnloadHook();

/**
 * 读shadowMap内存
 */
BOOL WINAPI shadowMap_ReadMem(PVOID addr, UCHAR *buf, ULONG size);

/**
 * 写shadowMap内存
 */
BOOL WINAPI shadowMap_WriteMem(PVOID addr, UCHAR *buf, ULONG size);

#endif
