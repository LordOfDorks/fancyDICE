/*
 * Firewall.c
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

extern DICE_HAL DiceHAL;

DICE_RC GetRandom(unsigned char* entropy, unsigned int size)
{
    uint32_t entropyWord;
    if(DiceHAL.phRng == NULL) return DICE_RC_Hardware_Error;
    for(uint32_t n = 0; n < size; n += sizeof(entropyWord))
    {
        if(HAL_RNG_GenerateRandomNumber(DiceHAL.phRng, &entropyWord) != HAL_OK)
        {
            return DICE_RC_Hardware_Error;
        }
        memcpy(&entropy[n], &entropyWord, MIN(sizeof(entropyWord), size - n));
    }
    return DICE_RC_OK;
}
