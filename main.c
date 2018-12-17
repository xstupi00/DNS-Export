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
#include "fsl_pit.h"

#define ROW_1_MASK  0x01000000
#define ROW_2_MASK  0x00000080
#define ROW_3_MASK  0x08000000
#define ROW_4_MASK  0x04000000
#define COL_1_MASK  0x10000000
#define COL_2_MASK  0x02000000
#define COL_3_MASK  0x20000000
#define PIEZZO_MASK 0x00000010

#define ROWS_KEYBOARD 		4
#define COLUMNS_KEYBOARD	3
#define BUTTONS			    12
#define BUTTON_KEY			5
#define MAX_ARR_SIZE 		127
#define LETTERS_NUMERALS	36
#define	MAX_MORSE_LEN		5

#define PIT_SOURCE_CLOCK CLOCK_GetFreq(kCLOCK_BusClk)

unsigned last_key = 0;
unsigned arr_index = 0;
int key_tap = -1;
char received_chars[MAX_ARR_SIZE];

char button_keys[BUTTONS][BUTTON_KEY] = {
		{'1'},
		{'A', 'B', 'C', '2'},
		{'D', 'E', 'F', '3'},
		{'G', 'H', 'I', '4'},
		{'J', 'K', 'L', '5'},
		{'M', 'N', 'O', '6'},
		{'P', 'R', 'S', 'Q', '7'},
		{'T', 'U', 'V', '8'},
		{'W', 'X', 'Y', 'Z', '9'},
		{'*'},
		{'0'},
		{'#'},
};

int morse_code[BUTTONS-2][BUTTON_KEY][MAX_MORSE_LEN] = {
		{ {0, 1, 1, 1, 1} }, 													  // 1
		{ {0, 1}, {1, 0, 0, 0}, {1, 0, 1, 0}, {0, 0, 1, 1, 1} }, 				  // A, B, C, 2
		{ {1, 0, 0}, {0}, {0, 0, 1, 0}, {0, 0, 0, 1, 1} }, 		 				  // D, E, F, 3
		{ {1, 1, 0}, {0, 0, 0, 0}, {0, 0}, {0, 0, 0, 0, 1} },	 				  // G, H, I, 4
		{ {0, 1, 1, 1}, {1, 0, 1}, {0, 1, 0, 0}, {0, 0, 0, 0, 0} },				  // J, K, L, 5
		{ {1, 1}, {1, 0}, {1, 1, 1}, {1, 0, 0, 0, 0} },							  // M, N, O, 6
		{ {0, 1, 1, 0}, {0, 1, 0}, {0, 0, 0}, {1, 1, 0, 1}, {1, 1, 0, 0, 0,} },	  // P, R, S, Q, 7
		{ {1}, {0, 0, 1}, {0, 0, 0, 1}, {1, 1, 1, 0, 0} },						  // T, U, V, 8
		{ {0, 1, 1}, {1, 0, 0, 1}, {1, 0, 1, 1}, {1, 1, 0, 0}, {1, 1, 1, 1, 0} }, // W, X, Y, Z, 9
		{ {1, 1, 1, 1, 1} }, 													  // 0
};

void delay(uint64_t bound) {
	for (uint64_t i=0; i < bound; i++) { __NOP(); }
}

void beep(void) {
    for (uint32_t q=0; q<500; q++) {
        GPIOA->PDOR |=  PIEZZO_MASK; delay(500);
        GPIOA->PDOR &= ~PIEZZO_MASK; delay(500);
    }
}


void Reset_PIT_Timer(void) {
	PIT_StopTimer(PIT, kPIT_Chnl_0);
	PIT_ClearStatusFlags(PIT, kPIT_Chnl_0, kPIT_TimerFlag);
	PIT_StartTimer(PIT, kPIT_Chnl_0);
}

void char_processing(void) {
	unsigned letters_count = 0;
	if (last_key == 7 || last_key == 9) {
		letters_count = 5;
	} else if (last_key == 2 || last_key == 3 || last_key == 4 || last_key == 5 || last_key == 6 || last_key == 8) {
		letters_count = 4;
	}
	unsigned idx = key_tap % letters_count;

	char ch = button_keys[last_key-1][idx];
	if (ch == '*' || ch == '#') {

	} else {
		received_chars[arr_index++] = ch;
	}
	key_tap = -1;

	for (unsigned i = 0; i < arr_index; i++) {
		PRINTF("%c ", received_chars[i]);
	}
    beep();
	PRINTF("\n");
}


void decode_char(int key) {
	if (key == 1 || key == 10 || key == 11 || key == 12) {
		key_tap++;
		last_key = key;
		char_processing();
	} else if (last_key == key || key_tap == -1) {
			key_tap++;
			last_key = key;
		    Reset_PIT_Timer();
	} else {
		char_processing();
		key_tap++;
		last_key = key;
	    Reset_PIT_Timer();
	}
}

void scanning_keyboard_rows(long COL_MASK, int array[4]) {
	GPIOA->PSOR = ROW_1_MASK;
	if (GPIOA->PDIR & COL_MASK) {
		decode_char(array[0]);
		GPIOA->PCOR = ROW_1_MASK;
	} else {
		GPIOA->PSOR = ROW_2_MASK;
		if (GPIOA->PDIR & COL_MASK) {
			decode_char(array[1]);
			GPIOA->PCOR = ROW_1_MASK | ROW_2_MASK;
		} else {
			GPIOA->PSOR = ROW_3_MASK;
			if (GPIOA->PDIR & COL_MASK) {
				decode_char(array[2]);
				GPIOA->PCOR = ROW_1_MASK | ROW_2_MASK | ROW_3_MASK;
			} else {
				GPIOA->PSOR = ROW_4_MASK;
				if (GPIOA->PDIR & COL_MASK) {
					decode_char(array[3]);
					GPIOA->PCOR = ROW_1_MASK | ROW_2_MASK | ROW_3_MASK | ROW_4_MASK;
				}
			}
		}
	}
}

void PIT0_IRQHandler(void) {
	/* Stop channel 0 */
	PIT_StopTimer(PIT, kPIT_Chnl_0);
    /* Clear channel 0 */
	PIT_ClearStatusFlags(PIT, kPIT_Chnl_0, kPIT_TimerFlag);
    char_processing();
}

void PORTA_IRQHandler(void) {
	delay(2000);

	// COL 1
	if (PORTA->ISFR & COL_1_MASK) {
		if (!(GPIOA->PDIR & COL_1_MASK)) {
			int arr[4] = {1, 4, 7, 10};
			scanning_keyboard_rows(COL_1_MASK, arr);
		}
		PORTA->ISFR |= COL_1_MASK;
		return;
	}

	// COL 2
	if (PORTA->ISFR & COL_2_MASK) {
		if (!(GPIOA->PDIR & COL_2_MASK)) {
			int arr[4] = {2, 5, 8, 11};
			scanning_keyboard_rows(COL_2_MASK, arr);
		}
		PORTA->ISFR |= COL_2_MASK;
		return;
	}

	// COL 3
	if (PORTA->ISFR & COL_3_MASK) {
		if (!(GPIOA->PDIR & COL_3_MASK)) {
			int arr[4] = {3, 6, 9, 12};
			scanning_keyboard_rows(COL_3_MASK, arr);
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

	// output rows == 0
	PORTA->PCR[7]  = PORT_PCR_MUX(0x01) | PORT_PCR_DSE(0x01);  // Pin Mux Control - row 2
	PORTA->PCR[27] = PORT_PCR_MUX(0x01) | PORT_PCR_DSE(0x01);  // Pin Mux Control - row 3
	PORTA->PCR[26] = PORT_PCR_MUX(0x01) | PORT_PCR_DSE(0x01);  // Pin Mux Control - row 4
	PORTA->PCR[24] = PORT_PCR_MUX(0x01) | PORT_PCR_DSE(0x01);  // Pin Mux Control - row 1
	PORTA->PCR[4]  = PORT_PCR_MUX(0x01) | PORT_PCR_DSE(0x01);
    GPIOA->PDDR |= ROW_1_MASK | ROW_2_MASK | ROW_3_MASK | ROW_4_MASK | PIEZZO_MASK;

	NVIC_ClearPendingIRQ(PORTA_IRQn); /* Nuluj priznak preruseni od portu B */
	NVIC_EnableIRQ(PORTA_IRQn);       /* Povol preruseni od portu B */
}

void PIT_Timer_Init(void) {
    /* Structure of initialize PIT */
    pit_config_t pitConfig;
    PIT_GetDefaultConfig(&pitConfig);
    /* Init pit module */
    PIT_Init(PIT, &pitConfig);
    /* Set timer period for channel 0 */
    PIT_SetTimerPeriod(PIT, kPIT_Chnl_0, USEC_TO_COUNT(1000000U, PIT_SOURCE_CLOCK));
    /* Enable timer interrupts for channel 0 */
    PIT_EnableInterrupts(PIT, kPIT_Chnl_0, kPIT_TimerInterruptEnable);
    /* Enable at the NVIC */
    NVIC_EnableIRQ(PIT0_IRQn);
}


/*
 * @brief   Application entry point.
 */
int main(void) {
	MCU_Init();
    PIT_Timer_Init();
    while (1);
}
