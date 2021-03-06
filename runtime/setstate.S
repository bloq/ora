/*
 * setstate.S
 *
 * Copyright 2017 Bloq Inc.
 *
 * The authors hereby grant permission to use, copy, modify, distribute,
 * and license this software and its documentation for any purpose, provided
 * that existing copyright notices are retained in all copies and that this
 * notice is included verbatim in any distributions. No written agreement,
 * license, or royalty fee is required for any of the authorized uses.
 * Modifications to this software may be copyrighted by their authors
 * and need not follow the licensing terms described here, provided that
 * the new terms are clearly indicated on the first page of each file where
 * they apply.
 */

/*
 * Input:
 * $r0	-- pointer to state buffer
 * $r1	-- length of state buffer
 *
 * Output:
 * none
 */

	.globl	setstate
	.type	setstate,@function
	.text
setstate:
	ssr	$r0, 8
	ssr	$r1, 9
	ret

.Lend:
	.size	setstate,.Lend-setstate
