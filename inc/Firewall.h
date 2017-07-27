/*
 * Firewall.h
 *
 *  Created on: Jun 9, 2017
 *      Author: stefanth
 */

#ifndef FIREWALL_H_
#define FIREWALL_H_

#define DICE_MAGIC 0x65636944 // 'Dice'

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif
#ifndef MAX
#define MAX(a,b) (((a)>(b))?(a):(b))
#endif

typedef struct
{
    RNG_HandleTypeDef* phRng;
    UART_HandleTypeDef* phUart;
} DICE_HAL, *pDICE_HAL;

typedef enum
{
    DICE_FID_NOOP = 0,
    DICE_FID_HalHandleTable,
    DICE_FID_GetRandom,
    DICE_FID_SHA256,
    DICE_FID_HMACSHA256,
    DICE_FID_MaxFunction
} DICE_FID, *pDICE_FID;

typedef enum
{
    DICE_RC_OK = 0,
    DICE_RC_Bad_FID,
    DICE_RC_Bad_Parameter,
    DICE_RC_Not_Implemented,
    DICE_RC_Hardware_Error,
    DICE_RC_MaxError
} DICE_RC, *pDICE_RC;

typedef union
{
    struct
    {
        DICE_HAL handleTable;
    } in;
    struct
    {
        DICE_HAL handleTable;
    } out;
} DICE_PARAM_HalHandleTable, *pDICE_PARAM_HalHandleTable;

typedef union
{
    struct
    {
        unsigned char* entropy;
        unsigned int size;
    } in;
    struct
    {
    } out;
} DICE_PARAM_GetRandom, *pDICE_PARAM_GetRandom;

typedef union
{
    struct
    {
        unsigned int segments;
        unsigned char** data;
        unsigned int* size;
        unsigned char* digest;
    } in;
    struct
    {
        unsigned char digest[32];
    } out;
} DICE_PARAM_SHA256, *pDICE_PARAM_SHA256;

typedef union
{
    struct
    {
        unsigned char* key;
        unsigned int keySize;
        unsigned int segments;
        unsigned char** data;
        unsigned int* dataSize;
        unsigned char* hmac;
    } in;
    struct
    {
        unsigned char hmac[32];
    } out;
} DICE_PARAM_HMACSHA256, *pDICE_PARAM_HMACSHA256;

typedef struct
{
    unsigned int magic;
    DICE_FID fid;
    unsigned int paramSize;
    DICE_RC result;
    union
    {
        DICE_PARAM_HalHandleTable HalHandleTable;
        DICE_PARAM_GetRandom GetRandom;
        DICE_PARAM_SHA256 SHA256;
        DICE_PARAM_HMACSHA256 HMACSHA256;
    } u;
} DICE_Context, *pDICE_Context;

typedef unsigned int (*CallGate_FPT)(pDICE_Context ctx);
#define FWCALLGATE(__ctx) ((CallGate_FPT)0x08000205)(__ctx)

#endif /* FIREWALL_H_ */
