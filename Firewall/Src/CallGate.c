/*
 * CallGate.cpp
 *
 *  Created on: Jun 9, 2017
 *      Author: stefanth
 */

#include <stdio.h>
#include <string.h>
#include "stm32l4xx_hal.h"
#include "..\..\inc\firewall.h"
#include "fwIntern.h"
#include "DiceSha256.h"
#include "DiceHmac.h"

DICE_HAL DiceHAL = {0};
static uint32_t CallGateResult;
static unsigned int outsideSP;
unsigned char secureStack[0x400];

__attribute__((section(".callgate"))) unsigned int CallGate(pDICE_Context ctx)
{
    // Switch the steack so we dont leave any secrets around
    register unsigned int sp_alias asm("sp");
    outsideSP = sp_alias;
    sp_alias = (unsigned int)&secureStack[sizeof(secureStack)];

    // Initialize the return
    CallGateResult = 0;

    // Parameter check
    if((ctx == NULL) || (ctx->magic != DICE_MAGIC))
    {
        CallGateResult = 1;
        goto Cleanup;
    }

    // Dispatch the requested function
    switch(ctx->fid)
    {
    case DICE_FID_NOOP:

        ctx->result = DICE_RC_OK;
        if(ctx->paramSize != 0)
        {
            ctx->result = DICE_RC_Bad_Parameter;
        }
        break;
    case DICE_FID_HalHandleTable:
        if(ctx->paramSize != sizeof(DICE_PARAM_HalHandleTable))
        {
            ctx->result = DICE_RC_Bad_Parameter;
        }
        else
        {
            if(ctx->u.HalHandleTable.in.handleTable.phRng != (RNG_HandleTypeDef*)-1)
                DiceHAL.phRng = ctx->u.HalHandleTable.in.handleTable.phRng;
            if(ctx->u.HalHandleTable.in.handleTable.phUart != (UART_HandleTypeDef*)-1)
                DiceHAL.phUart = ctx->u.HalHandleTable.in.handleTable.phUart;
            memcpy(&ctx->u.HalHandleTable.out.handleTable, &DiceHAL, sizeof(DICE_HAL));
            ctx->result = DICE_RC_OK;
        }
        break;
    case DICE_FID_GetRandom:
        if(ctx->paramSize != sizeof(DICE_PARAM_GetRandom))
        {
            ctx->result = DICE_RC_Bad_Parameter;
        }
        else
        {
            ctx->result = GetRandom(ctx->u.GetRandom.in.entropy, ctx->u.GetRandom.in.size);
        }
        break;
    case DICE_FID_SHA256:
        if(ctx->paramSize != sizeof(DICE_PARAM_SHA256))
        {
            ctx->result = DICE_RC_Bad_Parameter;
        }
        else
        {
            uint8_t* digestOut = ctx->u.SHA256.in.digest;
            DICE_SHA256_CONTEXT context = {0};
            Dice_SHA256_Init(&context);
            for(uint32_t n = 0; n < ctx->u.SHA256.in.segments; n++)
            {
                Dice_SHA256_Update(&context, ctx->u.SHA256.in.data[n], ctx->u.SHA256.in.size[n]);
            }
            Dice_SHA256_Final(&context, ctx->u.SHA256.out.digest);
            if(digestOut != NULL)
            {
                memcpy(digestOut, ctx->u.SHA256.out.digest, sizeof(ctx->u.SHA256.out.digest));
            }
            ctx->result = DICE_RC_OK;
        }
        break;
    case DICE_FID_HMACSHA256:
        if(ctx->paramSize != sizeof(DICE_PARAM_HMACSHA256))
        {
            ctx->result = DICE_RC_Bad_Parameter;
        }
        else
        {
            uint8_t* digestOut = ctx->u.HMACSHA256.in.hmac;
            DICE_HMAC_SHA256_CTX context = {0};
            Dice_HMAC_SHA256_Init(&context, ctx->u.HMACSHA256.in.key, ctx->u.HMACSHA256.in.keySize);
            for(uint32_t n = 0; n < ctx->u.HMACSHA256.in.segments; n++)
            {
                Dice_HMAC_SHA256_Update(&context, ctx->u.HMACSHA256.in.data[n], ctx->u.HMACSHA256.in.dataSize[n]);
            }
            Dice_HMAC_SHA256_Final(&context, ctx->u.HMACSHA256.out.hmac);
            if(digestOut != NULL)
            {
                memcpy(digestOut, ctx->u.HMACSHA256.out.hmac, sizeof(ctx->u.HMACSHA256.out.hmac));
            }
            ctx->result = DICE_RC_OK;
        }
        break;
    default:
        ctx->result = DICE_RC_Bad_FID;
        break;
    }

Cleanup:
    // Swap the stack back and return
    sp_alias = outsideSP;
    memset(secureStack, 0x00, sizeof(secureStack));
    return CallGateResult;
}

