// SPDX-License-Identifier: GPL-2.0
/*
 * User-space utility for the thunderbolt/USB4 subsystem
 *
 * This file provides the details of the retimers in the TBT/USB4
 * subsystem.
 *
 * Copyright (C) 2023 Rajat Khandelwal <rajat.khandelwal@intel.com>
 * Copyright (C) 2023 Intel Corporation
 */

#include <dirent.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "helpers.h"

/*
 * Check if the given string is in retimer string format.
 * Cases are limited for a thunderbolt directory.
 */
static bool is_retimer_format(const char *retimer, u8 domain)
{
	char num_str[MAX_LEN];
	char *colon_str = ":";
	int pos;

	snprintf(num_str, sizeof(num_str), "%u-", domain);

	pos = strpos(retimer, num_str, 0);
	if (pos)
		return false;

	pos = strpos(retimer, colon_str, 0);
	if (pos <= 0)
		return false;

	return true;
}

/*
 * Returns 'true' if the provided retimer is present in the given router,
 * 'false' otherwise.
 */
static bool is_retimer_in_router(const char *retimer, const char *router)
{
	char *rtr;
	int pos;

	pos = strpos(retimer, ":", 0);
	if (pos < 0)
		return false;

	rtr = get_substr(retimer, 0, pos);

	if (strcmp(rtr, router)) {
		free(rtr);
		return false;
	}

	free(rtr);

	return true;
}

/* Dumps the retimer f/w version */
static void dump_retimer_nvm_version(const char *retimer)
{
	char path[MAX_LEN], check[MAX_LEN];
	char *ver;
	size_t len;

	snprintf(check, sizeof(check), "%s%s/nvm_version", tbt_sysfs_path, retimer);
	if (is_link_nabs(check))
		exit(1);

	snprintf(path, sizeof(path), "%s%s/nvm_version", tbt_sysfs_path,
		 retimer);

	read_line_from_file(&ver, &len, path);
	printf("NVM %s\n", ver);

	free(ver);
}

/* Dumps the retimer */
static bool dump_retimer(const char *retimer)
{
	char vid_path[MAX_LEN], did_path[MAX_LEN], vcheck[MAX_LEN], dcheck[MAX_LEN];
	int pos, dot_pos;
	char *vid, *did;
	size_t vid_len, did_len;
	u8 domain, port;
	char *router;
	char *str;

	str = get_substr(retimer, 0, 1);
	domain = strtoud(str);
	free(str);

	pos = strpos(retimer, ":", 0);
	if (pos < 0)
		return false;

	router = get_substr(retimer, 0, pos);

	dot_pos = strpos(retimer, ".", pos);
	if (dot_pos < 0) {
		free(router);
		return false;
	}

	port = strtoud(get_substr(retimer, pos + 1, dot_pos - pos - 1));

	printf("Domain %u Router %s: Port %u: ", domain, router, port);

	snprintf(vcheck, sizeof(vcheck), "%s%s/vendor", tbt_sysfs_path, retimer);
	snprintf(dcheck, sizeof(dcheck), "%s%s/device", tbt_sysfs_path, retimer);
	if (is_link_nabs(vcheck) || is_link_nabs(dcheck))
		exit(1);

	snprintf(vid_path, sizeof(vid_path), "%s%s/vendor", tbt_sysfs_path, retimer);
	read_line_from_file(&vid, &vid_len, vid_path);

	snprintf(did_path, sizeof(did_path), "%s%s/device", tbt_sysfs_path, retimer);
	read_line_from_file(&did, &did_len, did_path);
	printf("ID %04x:%04x ", strtouh(vid), strtouh(did));

	dump_retimer_nvm_version(retimer);

	free(vid);
	free(did);
	free(router);

	return true;
}

/* Dumps the retimers (if any) present in the provided domain */
static bool enumerate_retimers_in_domain(u8 domain)
{
	DIR* dp;
	struct dirent* dir;
	bool found = false;

	dp = opendir(tbt_sysfs_path);

	for (; dir != NULL; dir = readdir(dp)) {
		if (!is_retimer_format(dir->d_name, domain))
			continue;

		found |= dump_retimer(dir->d_name);
	}

	closedir(dp);
	free(dir);

	return found;
}

/* Dumps the retimers (if any) present on any port in the provided router */
static bool dump_retimers_in_router(const char *router)
{
	DIR* dp;
	struct dirent* dir;
	bool found = false;
	u8 domain;
	char *str;

	str = get_substr(router, 0, 1);
	domain = strtoud(str);
	free(str);

	dp = opendir(tbt_sysfs_path);

	for (; dir != NULL; dir = readdir(dp)) {
		if (!is_retimer_format(dir->d_name, domain))
			continue;

		if (!is_retimer_in_router(dir->d_name, router))
			continue;

		found |= dump_retimer(dir->d_name);
	}

	closedir(dp);
	free(dir);

	return found;
}

static bool validate_args_r(char *domain, const char *depth, const char *device)
{
	u8 domains = total_domains();
	u8 i = 0;

	if (depth)
		return false;

	if (device) {
		if (domain)
			return false;
		else {
			for (; i < domains; i++) {
				if (is_router_format(device, i))
					return true;
			}

			return false;
		}
	}

	if (domain) {
		if (!isnum(domain) || strtoud(domain) >= domains)
			return false;
	}

	return true;
}

/* Function to be called with '-r' as the extra argument */
int lstbt_r(char *domain, const char *depth, char *device)
{
	u8 domains = total_domains();
	bool found = false;
	u8 i;

	if (!domains) {
		fprintf(stderr, "thunderbolt can't be found\n");
		return 1;
	}

	if (!validate_args_r(domain, depth, device)) {
		fprintf(stderr, "invalid argument(s)\n%s", help_msg);
		return 1;
	}

	if (device) {
		if (!is_router_present(device)) {
			fprintf(stderr, "invalid device\n");
			return 1;
		}

		found = dump_retimers_in_router(device);
	} else if (!domain) {
		i = 0;

		for (; i < domains; i++)
			found |= enumerate_retimers_in_domain(i);
	} else
		found = enumerate_retimers_in_domain(strtoud(domain));

	if (!found)
		printf("no retimer(s) found\n");

	return 0;
}
