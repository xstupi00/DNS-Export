/**************************************************************
 * Project:     Morse Code Encoder
 * File:		main.c
 * Author:		Šimon Stupinský
 * University: 	Brno University of Technology
 * Faculty: 	Faculty of Information Technology
 * Course:	    Microprocessors and Embedded Systems
 * Date:		14.12.2018
 * Last change:	18.12.2018
 *
 * Subscribe:	Main module of project, which implemented the encoder
 * 				of Morse Code. The chars to encode are given from the
 * 				keyboard, which is connected to FITkit3.
 *
 **************************************************************/

/**
 * @file    main.c
 * @brief   Application entry point.
 */

#include "MK60D10.h"
#include "fsl_pit.h"


/* Mapping of KEYBOARD buttons to specific port pins: */
#define ROW_1_MASK  0x01000000 ///< PORT A, bit 24 - KEYBOARD ROW 1
#define ROW_2_MASK  0x00000080 ///< PORT A, bit 07 - KEYBOARD ROW 2
#define ROW_3_MASK  0x08000000 ///< PORT A, bit 27 - KEYBOARD ROW 3
#define ROW_4_MASK  0x04000000 ///< PORT A, bit 26 - KEYBOARD ROW 4
#define COL_1_MASK  0x10000000 ///< PORT A, bit 28 - KEYBOARD COLUMN 1
#define COL_2_MASK  0x02000000 ///< PORT A, bit 25 - KEYBOARD COLUMN 2
#define COL_3_MASK  0x20000000 ///< PORT A, bit 29 - KEYBOARD COLUMN 3

/* Mapping of LEDs and REPRODUCTOR to specific port pins: */
#define LED_D9  0x20 		///< Port B, bit 5 - LED D9
#define LED_D10 0x10		///< Port B, bit 4 - LED D10
#define LED_D11 0x8 		///< Port B, bit 3 - LED D11
#define LED_D12 0x4 		///< Port B, bit 2 - LED D12
#define PIEZZO_MASK 0x10 	///< PORT A, bit 4, - REPRODUCTOR

/* Defining of constants needed in whole program part: */
#define ROWS_KEYBOARD 		4		///< count of rows on the keyboard
#define COLUMNS_KEYBOARD	3		///< count of the columns on the keyboard
#define BUTTONS			    12		///< count of individual buttons on the keyboard
#define BUTTON_KEY			5		///< maximal count of different letters on the one button
#define MAX_ARR_SIZE 		255		///< maximal size for all needed arrays
#define LETTERS_NUMBERS		36		///< count of supported letters and numbers
#define	MAX_MORSE_LEN		5		///< maximal length of the Morse Code
#define MORSE_DOT			0		///< represents the dot at Morse Code
#define MORSE_DASH			1		///< represents the dash at Morse Code
#define MORSE_SPACE			2		///< space between parts of the same letter
#define MORSE_PAUSE			3       ///< space between letters
#define MIN_MORSE_UNIT		400   	///< minimal frequency of reproducing the letters in Morse Code
#define MAX_MORSE_UNIT		2600	///< maximal frequency of reproducing the letters in Morse Code
#define MORSE_UNIT_GROWTH	100		///< the one growth of the frequency of reproducing changed by users

/* Defining source of the clock, which will be used by PIT (Period Interrupt Timer) */
#define PIT_SOURCE_CLOCK CLOCK_GetFreq(kCLOCK_BusClk)


/**
 * @brief	Compare two two values of the same types and returns greater from them
 *
 * @param 	a	first value of type T
 * @param 	b	second value of type T
 *
 * @return greater value from the given values
 */
 #define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })


/**
 * @brief	Compare two two values of the same types and returns lesser from them
 *
 * @param 	a	first value of type T
 * @param 	b	second value of type T
 *
 * @return lesser value from the given values
 */
 #define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

/* Defining the global variables to which is access from the different methods. */
unsigned MORSE_UNIT, NEW_MORSE_UNIT = 1500; ///< length of the Morse unit
unsigned last_key = 0;						///< last time pressed button with the its relevant key
unsigned store_index = 0;					///< index to the array of received chars to stored newly pressed chars
unsigned buzz_index = 0;					///< index to the array of received chars to recognition of the played chars
unsigned cache_index = 0;					///< index to the cache array to stored the chars for its playing
unsigned play_index = 0;					///< index to the cache array to recognition chars of the played chars
int key_tap = -1;							///< counter of the taps on the one button several times in a row

/* Defining the global arrays for the storing the receiving chars and its subsequently reproducing. */
unsigned buzz_cache[MAX_ARR_SIZE];			///< buffer of chars determines for the immediately reproducing
unsigned received_chars_key[MAX_ARR_SIZE];	///< buffer of the received chars

/* Mapping the individual Morse codes of letters, according to its location on the keyboard. */
int morse_codes[BUTTONS-2][BUTTON_KEY][MAX_MORSE_LEN] = {	///< buttons - 2 (except for '*' and '#')
		{ {0, 1, 1, 1, 1} }, 													  					// 1
		{ {0, 1, -1}, {1, 0, 0, 0, -1}, {1, 0, 1, 0, -1}, {0, 0, 1, 1, 1} }, 						// A, B, C, 2
		{ {1, 0, 0, -1}, {0, -1, -1, -1}, {0, 0, 1, 0, -1}, {0, 0, 0, 1, 1} }, 		 		 		// D, E, F, 3
		{ {1, 1, 0, -1}, {0, 0, 0, 0, -1}, {0, 0, -1}, {0, 0, 0, 0, 1} },	 		    			// G, H, I, 4
		{ {0, 1, 1, 1, -1}, {1, 0, 1, -1}, {0, 1, 0, 0, -1}, {0, 0, 0, 0, 0} },				    	// J, K, L, 5
		{ {1, 1, -1}, {1, 0, -1}, {1, 1, 1, -1}, {1, 0, 0, 0, 0} },									// M, N, O, 6
		{ {0, 1, 1, 0, -1}, {0, 1, 0, -1}, {0, 0, 0, -1}, {1, 1, 0, 1, -1}, {1, 1, 0, 0, 0} },		// P, R, S, Q, 7
		{ {1, -1}, {0, 0, 1, -1}, {0, 0, 0, 1, -1}, {1, 1, 1, 0, 0} },				   				// T, U, V, 8
		{ {0, 1, 1, -1}, {1, 0, 0, 1, -1}, {1, 0, 1, 1, -1}, {1, 1, 0, 0, -1}, {1, 1, 1, 1, 0} }, 	// W, X, Y, Z, 9
		{ {1, 1, 1, 1, 1} }, 													  					// 0
};


/*
 * @brief 	Realization of the active waiting, for simulating of the delay.
 *
 * @param	function has no parameters
 *
 * @return 	function has no return value
 */
void delay(uint64_t bound) {
	for (uint64_t i=0; i < bound; i++) { __NOP(); }
}


/*
 * @brief 	Realization the reproducing the individual Morse codes of the letters.
 *			Control the loudspeaker and the LEDs according to actual requirements.
 *
 * @param 	sound	represents the type of the required sound, with the relevant frequency and length
 *
 * @return 	function has no return value
 */
void beep(unsigned sound) {
	///< check whether the value of the frequency of reproducing was changed
	if (NEW_MORSE_UNIT != MORSE_UNIT) {
		MORSE_UNIT = NEW_MORSE_UNIT;
	}

	if (sound == MORSE_DOT) {	///< reproducing the Morse dot
		for (uint32_t q = 0; q < MORSE_UNIT; q++) { 	///< the length of a dot is ONE MORSE UNIT
			GPIOA->PSOR = PIEZZO_MASK; GPIOB->PDOR ^= LED_D9; delay(500);	///< ACTIVATION   (loudspeaker and LED - D9)
			GPIOA->PCOR = PIEZZO_MASK; GPIOB->PDOR ^= LED_D9; delay(500);	///< DEACTIVATION (loudspeaker and LED - D9)
		}
	} else if (sound == MORSE_DASH) { ///< reproducing the Morse dash
		for (uint32_t q = 0; q < 3*MORSE_UNIT; q++) { 	///< the length of a dash is THREE MORSE UNITS
			GPIOA->PSOR = PIEZZO_MASK; GPIOB->PDOR ^= LED_D10; delay(500);	///< ACTIVATION   (loudspeaker and LED - D10)
			GPIOA->PCOR = PIEZZO_MASK; GPIOB->PDOR ^= LED_D10; delay(500);  ///< DEACTIVATION   (loudspeaker and LED - D10)
		}
	} else if (sound == MORSE_SPACE) { ///< reproducing the space between parts of the same letter
		for (uint32_t q = 0; q < MORSE_UNIT; q++) { 	///< the length of the space is ONE UNIT
			GPIOB->PDOR ^= LED_D11; delay(1000); GPIOB->PDOR ^= LED_D11; ///< ACTIVATION and DEACTIVATION (LED - D11)
		}
	} else if (sound == MORSE_PAUSE) { ///< reproducing the space between letters
		for (uint32_t q = 0; q < 3*MORSE_UNIT; q++) {	///< the length of the space is THREEE UNITS
			GPIOB->PDOR ^= LED_D12; delay(1000); GPIOB->PDOR ^= LED_D12; ///< ACTIVATION and DEACTIVATION (LED - D12)
		}
	}
}


/*
 * @brief	Function executing the concatenation of two integer.
 *
 * @param 	x	first integer to concatenate	(e.g 5)
 * @param 	y	second integer to concatenate	(e.g 1)
 *
 * @return	function returns the integer after concatenation 	(e.g 51)
 */
unsigned concatenate_int(unsigned x, unsigned y) {
    unsigned pow = 10;
    while(y >= pow)
        pow *= 10;
    return x * pow + y;
}


/*
 * @brief 	Realization of the reactivation of PIT Timer.
 *
 * @param	function has no parameters
 *
 * @return 	function has no return value
 */
void Reset_PIT_Timer(void) {
	/* Stop PIT channel 0 */
	PIT_StopTimer(PIT, kPIT_Chnl_0);
	/* Clear flags at PIT channel 0 */
	PIT_ClearStatusFlags(PIT, kPIT_Chnl_0, kPIT_TimerFlag);
	/* Start PIT channel 0 */
	PIT_StartTimer(PIT, kPIT_Chnl_0);
}


/*
 * @brief 	Processing of the received decoding letters.
 *
 * @param	function has no parameters
 *
 * @return 	function has no return value
 */
void char_processing(void) {
	unsigned letters_count = 0;
	if (last_key == 7 || last_key == 9) {
		letters_count = 5;					///< buttons with the 5 variants of letters (7, 9)
	} else if (last_key == 2 || last_key == 3 || last_key == 4 || last_key == 5 || last_key == 6 || last_key == 8) {
		letters_count = 4;					///< buttons with the 4 variants of letters (2, 3, 4, 5, 6, 8)
	}

	if (last_key == 11) {			///< button '*' - slowing of the reproduction
		NEW_MORSE_UNIT = min(MAX_MORSE_UNIT, NEW_MORSE_UNIT+MORSE_UNIT_GROWTH);
	} else if (last_key == 12) { 	///< button '#' - speeding up of the reproduction
		NEW_MORSE_UNIT = max(MIN_MORSE_UNIT, NEW_MORSE_UNIT-MORSE_UNIT_GROWTH);
	} else {	///< store the indexes to the Morse Code map to buffer of the received letters
		received_chars_key[store_index++ % MAX_ARR_SIZE] = concatenate_int(last_key-1, key_tap % letters_count);
	}
	///< clear the button taping
	key_tap = -1;

}


/*
 * @brief Alternation switch of different activities with the received letter.
 *
 * @param 	key		Key of the received letter according to its position on the keyboard
 *
 * @return 	function has no return value
 *
 */
void decode_char(int key) {
	///< the button with only one variant of the letter, determines for immediately processing
	if (key == 1 || key == 10 || key == 11 || key == 12) {	///< 1, 0, '*', '#'
		key_tap++;			///< tap = 1
		last_key = key;		///< set the last key for the char_processing() function
		char_processing();
	} else if (last_key == key || key_tap == -1) { ///< repeatedly or first pressing the key
			key_tap++;			///< incrementing the key_tap
			last_key = key;		///< set the last key for the char_processing() function
		    Reset_PIT_Timer();	///< reset the timer for timeout to accept of pressed button
	} else {		///< pressing the another key as the last presser, without the expiration of timeout
		char_processing();		///< processing of the last presser button with relevant key
		key_tap++;				///< tap = 1
		last_key = key;			///< set the last key for the char_processing() function
	    Reset_PIT_Timer();		///< reset the timer for timeout to accept of pressed button
	}
}


/*
 * @brief 	Scanning of the individual keyboard rows to find the pressing button.
 *
 * @param	COL_MASK	mask of the currently detected rows, on which is the pressing button
 * @param	array[4]	array with the buttons on current detected column for its subsequently processing
 *
 * @return	function has no return value
 */
void scanning_keyboard_rows(long COL_MASK, int array[4]) {
	///< checking the first row
	GPIOA->PSOR = ROW_1_MASK;
	if (GPIOA->PDIR & COL_MASK) {
		///< button pressed on the first row
		decode_char(array[0]);
		///< clearing the set flags on the relevant row (1)
		GPIOA->PCOR = ROW_1_MASK;
	///< unsuccessful checking at first row -> checking the second row
	} else {
		///< checking the second row
		GPIOA->PSOR = ROW_2_MASK;
		if (GPIOA->PDIR & COL_MASK) {
			///< button pressed on the second row
			decode_char(array[1]);
			///< clearing the set flags on the relevant row (1, 2)
			GPIOA->PCOR = ROW_1_MASK | ROW_2_MASK;
		///< unsuccessful checking at first and second rows -> checking the third rows
		} else {
			///< checking the third row
			GPIOA->PSOR = ROW_3_MASK;
			if (GPIOA->PDIR & COL_MASK) {
				///< button pressed on the third row
				decode_char(array[2]);
				///< clearing the set flags on the relevant row (1, 2, 3)
				GPIOA->PCOR = ROW_1_MASK | ROW_2_MASK | ROW_3_MASK;
			///< unsuccessful checking at first, second and third row -> checking the fourth rows
			} else {
				///< checking the fourth row
				GPIOA->PSOR = ROW_4_MASK;
				if (GPIOA->PDIR & COL_MASK) {
					///< button pressed on the third row
					decode_char(array[3]);
					///< clearing the set flags on the relevant row (1, 2, 3, 4)
					GPIOA->PCOR = ROW_1_MASK | ROW_2_MASK | ROW_3_MASK | ROW_4_MASK;
				}
			}
		}
	}
}


/*
 * @brief 	PIT0 Channel Interrupt IRQ Handler executing the relevant actions after
 *          expiration of the timeout (clear the PIT Timer and processing the currently letter)
 *
 * @param	function has no parameters
 *
 * @return 	function has no return value
 */
void PIT0_IRQHandler(void) {
	/* Stop channel 0 */
	PIT_StopTimer(PIT, kPIT_Chnl_0);
    /* Clear channel 0 */
	PIT_ClearStatusFlags(PIT, kPIT_Chnl_0, kPIT_TimerFlag);
	/* Processing of the received char */
    char_processing();
}


/*
 * @brief 	PORT A Interrupt IRQ Handler executing the selection of
 * 			the columns on the keyboard, on which is currently pressing the button.
 * 			Selection the column on which was caused the interruption.
 *
 * @param	function has no parameters
 *
 * @return 	function has no return value
 */
void PORTA_IRQHandler(void) {
	delay(2000);
	// COLUMN 1
	if (PORTA->ISFR & COL_1_MASK) {
		///< ignore the button flicker, acceptation only pressed
		if (!(GPIOA->PDIR & COL_1_MASK)) {
			///< buttons on the first column (1, 4, 7, '*')
			int arr[4] = {1, 4, 7, 11};
			///< scanning the keyboard rows
			scanning_keyboard_rows(COL_1_MASK, arr);
		}
		///< clearing the interruption flags
		PORTA->ISFR |= COL_1_MASK;
		return;
	}

	// COLUMN 2
	if (PORTA->ISFR & COL_2_MASK) {
		///< ignore the button flicker, acceptation only pressed
		if (!(GPIOA->PDIR & COL_2_MASK)) {
			///< buttons on the second column (2, 5, 8, 0)
			int arr[4] = {2, 5, 8, 10};
			///< scanning the keyboard rows
			scanning_keyboard_rows(COL_2_MASK, arr);
		}
		///< clearing the interruption flags
		PORTA->ISFR |= COL_2_MASK;
		return;
	}

	// COLUMN 3
	if (PORTA->ISFR & COL_3_MASK) {
		///< ignore the button flicker, acceptation only pressed
		if (!(GPIOA->PDIR & COL_3_MASK)) {
			///< buttons on the third column (3, 6, 9, '#')
			int arr[4] = {3, 6, 9, 12};
			///< scanning the keyboard rows
			scanning_keyboard_rows(COL_3_MASK, arr);
		}
		///< clearing the interruption flags
		PORTA->ISFR |= COL_3_MASK;
		return;
	}
}


/**
 * @brief	Function executing the encoding the received letters to Morse Code.
 *
 * @param	function has no parameters
 *
 * @return 	function has no return value
 */
void filling_buzz_cache(void) {
	///< checking whether the buffer contains the letters for encoding
	if (buzz_index != store_index && cache_index == play_index) {
		///< obtains the column index to the Morse map
		unsigned col_index = received_chars_key[buzz_index] % 10;
		///< obtains the row index to the Morse map
		unsigned row_index = (received_chars_key[buzz_index++] / 10) % 10;

		unsigned cnt = 0;
		///< store the individual parts of the letter to the cache for its reproducing
		while (morse_codes[row_index][col_index][cnt] != -1 && cnt != 5) {
			///< storing the individual part according to Morse map at relevant position
			buzz_cache[cache_index++ % MAX_ARR_SIZE] = morse_codes[row_index][col_index][cnt++];
			///< storing the space between parts of the same letter
			buzz_cache[cache_index++ % MAX_ARR_SIZE] = MORSE_SPACE;
		}
		///< rewrite the space between parts of the same letter with the space between letters
		buzz_cache[cache_index-1 % MAX_ARR_SIZE] = MORSE_PAUSE;
	}

	///< checking whether the cache contains the part to the reproducing
	if (cache_index != play_index) {
		beep(buzz_cache[play_index++ % MAX_ARR_SIZE]);
	}
}


/**
 * @brief	Hardware initialization.
 *
 * @param	function has no parameters
 *
 * @return 	function has no return value
 */
void MCU_Init(void) {
	/* Activation the clock for PORT A and PORT B */
    SIM->SCGC5 |= SIM_SCGC5_PORTA_MASK | SIM_SCGC5_PORTB_MASK;
    /* Set clock sub-system */
    MCG->C4 |= ( MCG_C4_DMX32_MASK | MCG_C4_DRST_DRS(0x01) );
    SIM->CLKDIV1 |= SIM_CLKDIV1_OUTDIV1(0x00);
    /* Turn-Off WatchDog */
    WDOG->STCTRLH &= ~WDOG_STCTRLH_WDOGEN_MASK;

    /* Initialization of the Input Pins */
    int columns_idx[COLUMNS_KEYBOARD] = {25, 28, 29};
    for (uint8_t i = 0; i < COLUMNS_KEYBOARD; i++) {
		PORTA->PCR[columns_idx[i]] = ( PORT_PCR_ISF(0x01) 	/* Clear ISF (Interrupt Status Flag) */
						 | PORT_PCR_IRQC(0x0A) 				/* Interrupt enable on failing edge */
						 | PORT_PCR_MUX(0x01) 				/* Pin Mux Control to GPIO */
						 | PORT_PCR_PE(0x01) 				/* Pull resistor enable... */
						 | PORT_PCR_PS(0x01)); 				/* ...select Pull-Up */
	}

    /* Initialization of the Output Pins */

    /* Set corresponding PTA pins (connected to KEYBOARD) for GPIO functionality */
	PORTA->PCR[7]  = PORT_PCR_MUX(0x01) | PORT_PCR_DSE(0x01);  // Pin Mux Control - row 2
	PORTA->PCR[27] = PORT_PCR_MUX(0x01) | PORT_PCR_DSE(0x01);  // Pin Mux Control - row 3
	PORTA->PCR[26] = PORT_PCR_MUX(0x01) | PORT_PCR_DSE(0x01);  // Pin Mux Control - row 4
	PORTA->PCR[24] = PORT_PCR_MUX(0x01) | PORT_PCR_DSE(0x01);  // Pin Mux Control - row 1
	PORTA->PCR[4]  = PORT_PCR_MUX(0x01) | PORT_PCR_DSE(0x01);

    /* Set corresponding PTB pins (connected to LED's) for GPIO functionality */
    PORTB->PCR[5] = PORT_PCR_MUX(0x01); // LED - D9
    PORTB->PCR[4] = PORT_PCR_MUX(0x01); // LED - D10
    PORTB->PCR[3] = PORT_PCR_MUX(0x01); // LED - D11
    PORTB->PCR[2] = PORT_PCR_MUX(0x01); // LED - D12

    /* Change corresponding PTB and PTA ports GPIO pins as outputs */
    GPIOA->PDDR |= ROW_1_MASK | ROW_2_MASK | ROW_3_MASK | ROW_4_MASK | PIEZZO_MASK;
    GPIOB->PDDR |= LED_D9 | LED_D10 |LED_D11 | LED_D12;
    GPIOB->PDOR |= LED_D9 | LED_D10 |LED_D11 | LED_D12; ///< turn all LEDs OFF

	NVIC_ClearPendingIRQ(PORTA_IRQn); ///< Clear the interrupts from the PORT A
	NVIC_EnableIRQ(PORTA_IRQn);       ///< Enable interrupt from the PORT A
}


/**
 * @brief	PIT Module initialization.
 *
 * @param	function has no parameters
 *
 * @return 	function has no return value
 */
void PIT_Timer_Init(void) {
    /* Structure of initialize PIT */
    pit_config_t pitConfig;
    PIT_GetDefaultConfig(&pitConfig);
    /* Init PIY module */
    PIT_Init(PIT, &pitConfig);
    /* Set timer period for channel 0 */
    PIT_SetTimerPeriod(PIT, kPIT_Chnl_0, USEC_TO_COUNT(1000000U, PIT_SOURCE_CLOCK));
    /* Enable timer interrupts for channel 0 */
    PIT_EnableInterrupts(PIT, kPIT_Chnl_0, kPIT_TimerInterruptEnable);
    /* Enable at the NVIC */
    NVIC_EnableIRQ(PIT0_IRQn);
}


/*
 * @brief	Application entry point.
 */
int main(void) {
	MCU_Init();
    PIT_Timer_Init();
    while (1) {
    	filling_buzz_cache();
    }
}
