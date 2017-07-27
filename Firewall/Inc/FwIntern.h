/*
 * FwIntern.h
 *
 *  Created on: Jun 9, 2017
 *      Author: stefanth
 */

#ifndef FWINTERN_H_
#define FWINTERN_H_

unsigned int CallGate(pDICE_Context ctx);
DICE_RC GetRandom(unsigned char* entropy, unsigned int size);

#endif /* FWINTERN_H_ */
