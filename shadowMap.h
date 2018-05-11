#ifndef _SHADOW_MAP_H
#define _SHADOW_MAP_H


/**
 * ��װhook
 */
BOOL WINAPI shadowMap_InstallHook(HMODULE hModule);

/**
* ж��Hook
*/
BOOL WINAPI shadowMap_UnloadHook();

/**
 * ��shadowMap�ڴ�
 */
BOOL WINAPI shadowMap_ReadMem(PVOID addr, UCHAR *buf, ULONG size);

/**
 * дshadowMap�ڴ�
 */
BOOL WINAPI shadowMap_WriteMem(PVOID addr, UCHAR *buf, ULONG size);

#endif
