/*
 * Copyright 2016-2018 NXP Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * o Redistributions of source code must retain the above copyright notice, this list
 *   of conditions and the following disclaimer.
 *
 * o Redistributions in binary form must reproduce the above copyright notice, this
 *   list of conditions and the following disclaimer in the documentation and/or
 *   other materials provided with the distribution.
 *
 * o Neither the name of NXP Semiconductor, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
 
/**
 * @file    MK60DN512xxx10_Project.c
 * @brief   Application entry point.
 */
#include <stdio.h>
#include "board.h"
#include "peripherals.h"
#include "pin_mux.h"
#include "clock_config.h"
#include "MK60D10.h"
#include "fsl_debug_console.h"
#include "core_cm4.h"

unsigned cnt = 0;

#define ROW_1_MASK 0x01000000
#define ROW_2_MASK 0x00000080
#define ROW_3_MASK 0x08000000
#define ROW_4_MASK 0x04000000

#define COL_1_MASK 0x10000000
#define COL_2_MASK 0x02000000
#define COL_3_MASK 0x20000000

#define ROWS_KEYBOARD 		4
#define COLUMNS_KEYBOARD	3

void delay(uint64_t bound) {
	for (uint64_t i=0; i < bound; i++) { __NOP(); }
}

void PORTA_IRQHandler(void) {
	delay(2000);

	// COL 1
	if (PORTA->ISFR & COL_1_MASK) {
		if (!(GPIOA->PDIR & COL_1_MASK)) {
			PRINTF("COL 1\n");
		}
		PORTA->ISFR |= COL_1_MASK;
		return;
	}

	// COL 2
	if (PORTA->ISFR & COL_2_MASK) {
		if (!(GPIOA->PDIR & COL_2_MASK)) {
			PRINTF("COL 2\n");
		}
		PORTA->ISFR |= COL_2_MASK;
		return;
	}

	// COL 3
	if (PORTA->ISFR & COL_3_MASK) {
		if (!(GPIOA->PDIR & COL_3_MASK)) {
			PRINTF("COL 3\n");
		}
		PORTA->ISFR |= COL_3_MASK;
		return;
	}
}

void MCU_Init(void) {
    SIM->SCGC5 |= SIM_SCGC5_PORTA_MASK;
    MCG->C4 |= ( MCG_C4_DMX32_MASK | MCG_C4_DRST_DRS(0x01) );
    SIM->CLKDIV1 |= SIM_CLKDIV1_OUTDIV1(0x00);
    WDOG->STCTRLH &= ~WDOG_STCTRLH_WDOGEN_MASK;

    int columns_idx[COLUMNS_KEYBOARD] = {25, 28, 29};
    for (uint8_t i = 0; i < COLUMNS_KEYBOARD; i++) {
    	PORTA->PCR[columns_idx[i]] = ( PORT_PCR_ISF(0x01) /* Nuluj ISF (Interrupt Status Flag) */
    					 | PORT_PCR_IRQC(0x0A) /* Interrupt enable on failing edge */
						 | PORT_PCR_MUX(0x01) /* Pin Mux Control to GPIO */
						 | PORT_PCR_PE(0x01) /* Pull resistor enable... */
						 | PORT_PCR_PS(0x01)); /* ...select Pull-Up */
    }

    PORTA->PCR[7]  |= PORT_PCR_MUX(0x01);  // Pin Mux Control - row 2
    PORTA->PCR[27] |= PORT_PCR_MUX(0x01);  // Pin Mux Control - row 3
    PORTA->PCR[26] |= PORT_PCR_MUX(0x01);  // Pin Mux Control - row 4
    PORTA->PCR[24] |= PORT_PCR_MUX(0x01);  // Pin Mux Control - row 1
    GPIOA->PDDR |= ROW_1_MASK | ROW_2_MASK | ROW_3_MASK | ROW_4_MASK;

	NVIC_ClearPendingIRQ(PORTA_IRQn); /* Nuluj priznak preruseni od portu B */
	NVIC_EnableIRQ(PORTA_IRQn);       /* Povol preruseni od portu B */
}


/*
 * @brief   Application entry point.
 */
int main(void) {
    MCU_Init();
    while (1) ;
}
