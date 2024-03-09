// SPDX-License-Identifier: LGPL-2.0
/*
 * Example to demonstrate the transmission of DMA packets to a router.
 * This sample code transmits a read control packet to read 1 dword from the host
 * router of domain 0.
 *
 * To build and run:
 * gcc -g -Wall -W example.c tbtutils.c passthrough.c pciutils.c utils.c -o test
 * sudo ./test
 *
 * Copyright (C) 2023 Rajat Khandelwal <rajat.khandelwal@intel.com>
 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

#include "utils.h"

int main(void) {
	char* s = NULL;
	size_t len = 0;
	if (read_line_from_file(&s, &len, "/tmp/a") < 0) return 1;
	printf("%s", s);
	if (s == NULL) return 1;
	if (write_line_to_file(s, "/tmp/b") < 0) return 1;
	printf("%s", s);
	int i = count_files_in_dir_with("systemd", "/tmp");
	printf("%d\n", i);
	return 0;
}

